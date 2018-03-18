#include <dr_api.h>
#include <drmgr.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>


/* Single list of module_data_t */
typedef struct mods
{
    uint8_t *name;
    app_pc start;
    app_pc end;
    struct mods *next;
} mods_t;

/* Vars */
static mods_t 
* g_head;

static uint16_t
* instr_count;

/* Funcs */
static void
event_exit(void)
{
    drmgr_exit();
    dr_printf("Exiting...\n");
}

static
bool add_new_module(mods_t *head, const module_data_t *mod)
{
    /* Locals */
    mods_t *tmp = head;
    mods_t *prev;

    /* Iterate through list */
    while(true)
    {
        /* Check for end */
        if(tmp->next == NULL)
        {
            /* Create new node */
            prev = tmp;
            tmp = (mods_t *) malloc(sizeof(mods_t));

            /* Check for name */
            if(mod->names.module_name)
            {
                uint8_t len = strlen(mod->names.module_name) + 1;
                uint8_t *name = (uint8_t *) malloc(len);  
                sprintf(name, "%s", mod->names.module_name);
                memset(name + len - 1, 0, 1);
                tmp->name = name;
            }
            else
            {   
                uint8_t *name = (uint8_t *) malloc(5);
                sprintf(name, "NILL");
                memset(name + 4, 0, 1);
                tmp->name = name;
            }
            
            /* Update addresses */
            tmp->start = mod->start;
            tmp->end = mod->end;

            /* Update next pointer */
            tmp->next = NULL;
            prev->next = tmp;

            /* Debug */
            dr_printf("[*] Added new node\n");
            dr_printf("[*] Name: %s\n", tmp->name);
            dr_printf("[*] Start: %p\n", tmp->start);
            dr_printf("[*] End: %p\n", tmp->end);

            break;
        }

        tmp = tmp->next;
    }
}

static
void module_load_event(void *drcontext, const module_data_t *mod, bool loaded)
{
    /* Assign name */
    bool ret = add_new_module(g_head, mod);
}

static dr_emit_flags_t
event_bb_insert(void *drcontext, void *tag, instrlist_t *bb,
                instr_t *instr, bool for_trace, bool translating,
                void *user_data)
{
    if (instr_get_app_pc(instr) == NULL || !instr_is_app(instr))
        return DR_EMIT_DEFAULT;
    
    app_pc in = (app_pc) instr_get_app_pc(instr);
    mods_t *tmp = g_head;

    while(true)
    {
        if(in >= tmp->start && in <= tmp->end)
        {
            dr_printf("Instr: %p (%p) - Module: %s\n", 
                      in, 
                      (app_pc) ((size_t) in - (size_t) tmp->start), 
                      tmp->name);
            break;
        }

        tmp = tmp->next;
        if(tmp == NULL)
            break;
    }

    return DR_EMIT_DEFAULT;
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("mmtracer", "http://dynamorio.org/issues");

    /* make it easy to tell, by looking at log file, which client executed */
    dr_log(NULL, LOG_ALL, 1, "Client 'wrap' initializing\n");
    
    /* Get load address */
    g_head = (mods_t *) dr_global_alloc(sizeof(mods_t));
    module_data_t *main_mod = dr_get_main_module();
    g_head->next = NULL;

    /* Initialise */
    instr_count = (uint16_t *) dr_global_alloc(65536);
    memset(instr_count, 0, 65536);
    drmgr_init();
    dr_register_exit_event(event_exit);
    drmgr_register_module_load_event((void *) module_load_event);
    drmgr_register_bb_instrumentation_event(NULL,
                                            (void *) event_bb_insert,
                                            NULL);
 
}
