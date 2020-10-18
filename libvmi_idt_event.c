#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>

#define PAGE_SIZE 1 << 12

vmi_event_t idt_hooking_event;

static int interrupted = 0;
static void close_handler(int sig)
{
    interrupted = sig;
}

void print_event(vmi_event_t event)
{
    printf("PAGE ACCESS: %c%c%c for GFN %"PRIx64" (offset %06"PRIx64") gla %016"PRIx64" (vcpu %"PRIu32")\n",
           (event.mem_event.out_access & VMI_MEMACCESS_R) ? 'r' : '-',
           (event.mem_event.out_access & VMI_MEMACCESS_W) ? 'w' : '-',
           (event.mem_event.out_access & VMI_MEMACCESS_X) ? 'x' : '-',
           event.mem_event.gfn,
           event.mem_event.offset,
           event.mem_event.gla,
           event.vcpu_id
          );
}

event_response_t idt_hooking(vmi_instance_t vmi, vmi_event_t *event)
{
    

    printf("idt hooking detected\n");

    print_event(*event);

    vmi_clear_event(vmi, event, NULL);
    return 0;
}


int main (int argc, char **argv)
{
    vmi_instance_t vmi = NULL;
    status_t status = VMI_SUCCESS;
    addr_t idt_addr;
    addr_t phys_idtr = 0;
    struct sigaction act;


    char *name = NULL;

    vmi_init_data_t *init_data = NULL;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <name of VM> [<socket>]\n", argv[0]);
        exit(1);
    }

    // Arg 1 is the VM name.
    name = argv[1];

    if (argc == 3) {
        char *path = argv[2];

        init_data = malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
        init_data->count = 1;
        init_data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
        init_data->entry[0].data = strdup(path);
    }

    /* for a clean exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    /* initialize the libvmi library */
    if (VMI_FAILURE ==
            vmi_init_complete(&vmi, name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS,
                              init_data, VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL)) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    printf("LibVMI init succeeded!\n");

    // Get the value of lstar and cstar for the system.
    // NOTE: all vCPUs have the same value for these registers
    vmi_get_vcpureg(vmi, &idt_addr, IDTR_BASE, 0);
    printf("idt address == %llx\n", (unsigned long long)idt_addr);
    

    /* Per Linux ABI, this VA represents the start of the vsyscall page
     *  If vsyscall support is enabled (deprecated or disabled on many newer
     *  3.0+ kernels), it is accessible at this address in every process.
     */

    // Translate to a physical address.
    
    vmi_translate_kv2p(vmi, idt_addr, &phys_idtr);
    printf("Physical idt address == %llx\n", (unsigned long long)phys_idtr);
    

    

    // Setup a default event for tracking memory at the syscall handler.
    memset(&idt_hooking_event, 0, sizeof(vmi_event_t));
    idt_hooking_event.version = VMI_EVENTS_VERSION;
    idt_hooking_event.type = VMI_EVENT_MEMORY;
    idt_hooking_event.mem_event.gfn = phys_idtr >> 12;
    idt_hooking_event.mem_event.in_access = VMI_MEMACCESS_W;
    idt_hooking_event.callback=idt_hooking;
    
    
    if ( phys_idtr && VMI_FAILURE == vmi_register_event(vmi, &idt_hooking_event) )
        printf("Failed to register memory event on idt_hooking_event page\n");

    while (!interrupted) {
        printf("Waiting for events...\n");
        status = vmi_events_listen(vmi,500);
        if (status != VMI_SUCCESS) {
            printf("Error waiting for events, quitting...\n");
            interrupted = -1;
        }
    }

    vmi_pause_vm(vmi);

    // Process any events that may have been left
    if ( vmi_are_events_pending(vmi) > 0 )
        vmi_events_listen(vmi, 0);

    vmi_clear_event(vmi, &idt_hooking_event, NULL);

    vmi_resume_vm(vmi);

    printf("Finished with test.\n");

    // cleanup any memory associated with the libvmi instance
    vmi_destroy(vmi);

    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }

    return 0;
}
