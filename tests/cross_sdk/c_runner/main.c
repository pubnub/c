/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#include "common.h"

#include <stdio.h>
#include <string.h>

/* Forward declarations for all scenario run functions. */
xs_result_t run_c_publish(const xs_context_t* ctx);
xs_result_t run_c_compressed_publish(const xs_context_t* ctx);
xs_result_t run_c_json_publish(const xs_context_t* ctx);
xs_result_t run_c_encrypted_publish(const xs_context_t* ctx);
xs_result_t run_c_file_upload(const xs_context_t* ctx);
xs_result_t run_c_encrypted_file_upload(const xs_context_t* ctx);
xs_result_t run_c_set_uuid_metadata(const xs_context_t* ctx);
xs_result_t run_c_set_channel_metadata(const xs_context_t* ctx);
xs_result_t run_c_add_message_action(const xs_context_t* ctx);
xs_result_t run_c_presence_state_set(const xs_context_t* ctx);
xs_result_t run_c_channel_groups_add(const xs_context_t* ctx);
xs_result_t run_js_publish_verify(const xs_context_t* ctx);
xs_result_t run_js_encrypted_verify(const xs_context_t* ctx);
xs_result_t run_js_file_verify(const xs_context_t* ctx);
xs_result_t run_js_metadata_verify(const xs_context_t* ctx);
xs_result_t run_js_json_verify(const xs_context_t* ctx);
xs_result_t run_js_encrypted_file_verify(const xs_context_t* ctx);
xs_result_t run_js_channel_metadata_verify(const xs_context_t* ctx);
xs_result_t run_js_message_action_verify(const xs_context_t* ctx);
xs_result_t run_cleanup(const xs_context_t* ctx);

typedef xs_result_t (*scenario_fn_t)(const xs_context_t*);

typedef struct {
    const char*   name;
    scenario_fn_t fn;
} scenario_entry_t;

static const scenario_entry_t SCENARIOS[] = {
    {"c_publish",                  run_c_publish                 },
    {"c_compressed_publish",       run_c_compressed_publish      },
    {"c_json_publish",             run_c_json_publish            },
    {"c_encrypted_publish",        run_c_encrypted_publish       },
    {"c_file_upload",              run_c_file_upload             },
    {"c_encrypted_file_upload",    run_c_encrypted_file_upload   },
    {"c_set_uuid_metadata",        run_c_set_uuid_metadata       },
    {"c_set_channel_metadata",     run_c_set_channel_metadata    },
    {"c_add_message_action",       run_c_add_message_action      },
    {"c_presence_state_set",       run_c_presence_state_set      },
    {"c_channel_groups_add",       run_c_channel_groups_add      },
    {"js_publish_verify",          run_js_publish_verify         },
    {"js_encrypted_verify",        run_js_encrypted_verify       },
    {"js_file_verify",             run_js_file_verify            },
    {"js_metadata_verify",         run_js_metadata_verify        },
    {"js_json_verify",             run_js_json_verify            },
    {"js_encrypted_file_verify",   run_js_encrypted_file_verify  },
    {"js_channel_metadata_verify", run_js_channel_metadata_verify},
    {"js_message_action_verify",   run_js_message_action_verify  },
    {"cleanup",                    run_cleanup                   },
    {NULL,                         NULL                          },
};

int main(int argc, char* argv[])
{
    xs_context_t ctx = {0};
    if (0 != xs_parse_args(argc, argv, &ctx)) {
        (void)fprintf(stderr,
                      "Usage: cross_sdk_c_runner --scenario <name> "
                      "--channel <ch> --sub-key <key> --pub-key <key> "
                      "[--cipher <key>] [--uuid <uuid>] "
                      "[--content <str>] [--output <path>]\n");
        return 1;
    }

    for (const scenario_entry_t* e = SCENARIOS; NULL != e->name; ++e) {
        if (0 == strcmp(e->name, ctx.scenario)) {
            xs_result_t r = e->fn(&ctx);
            xs_write_result(&ctx, &r);
            return r.pass ? 0 : 1;
        }
    }

    (void)fprintf(stderr, "Unknown scenario: %s\n", ctx.scenario);
    return 1;
}
