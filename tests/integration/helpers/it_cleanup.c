/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "it_cleanup.h"

#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/future.h"
#include "pubnub/features/app_context.h"
#include "pubnub/features/channel_groups.h"
#include "pubnub/features/files.h"
#include "pubnub/features/history.h"
#include "pubnub/features/push.h"
#include "core/pn_string.h"

#include <cmocka.h>
#include <string.h>

/** Maximum number of files processed per page in LIST_DELETE_FILES. */
#define PN_IT_MAX_FILES_PER_PAGE 32U

static const char* it_cleanup_kind_str(it_cleanup_kind_t kind)
{
    switch (kind) {
    case IT_CLEANUP_DELETE_MESSAGES: return "delete_messages";
    case IT_CLEANUP_DELETE_FILE: return "delete_file";
    case IT_CLEANUP_LIST_DELETE_FILES: return "list_delete_files";
    case IT_CLEANUP_REMOVE_CHANNEL_GROUP: return "remove_channel_group";
    case IT_CLEANUP_REMOVE_UUID_METADATA: return "remove_uuid_metadata";
    case IT_CLEANUP_REMOVE_CHANNEL_METADATA: return "remove_channel_metadata";
    case IT_CLEANUP_REMOVE_MEMBERS: return "remove_members";
    case IT_CLEANUP_REMOVE_MEMBERSHIPS: return "remove_memberships";
    case IT_CLEANUP_REMOVE_PUSH_DEVICE: return "remove_push_device";
    default: return "unknown";
    }
}

static void it_cleanup_run_entry(pubnub_context_t* ctx, const it_cleanup_entry_t* e)
{
    pubnub_future_t fut        = PUBNUB_FUTURE_INVALID;
    int             dispatched = 0;
    pubnub_res_t    st;

    switch (e->kind) {
    case IT_CLEANUP_DELETE_MESSAGES: {
        if (PUBNUB_ENABLE_HISTORY) {
            pubnub_delete_messages_opts_t opts = PUBNUB_DELETE_MESSAGES_OPTS_INIT;
            opts.channel = e->a;
            fut          = pubnub_delete_messages(ctx, &opts);
            dispatched   = 1;
        }
        break;
    }
    case IT_CLEANUP_DELETE_FILE: {
        if (PUBNUB_ENABLE_FILES) {
            pubnub_delete_file_opts_t opts = PUBNUB_DELETE_FILE_OPTS_INIT;
            /* file_name approximated from file_id — cleanup is best-effort */
            opts.channel   = e->a;
            opts.file_id   = e->b;
            opts.file_name = e->b;
            fut            = pubnub_delete_file(ctx, &opts);
            dispatched     = 1;
        }
        break;
    }
    case IT_CLEANUP_LIST_DELETE_FILES: {
        if (PUBNUB_ENABLE_FILES) {
            pubnub_list_files_opts_t   lopts = PUBNUB_LIST_FILES_OPTS_INIT;
            pubnub_future_t            lfut;
            pubnub_res_t               lst;
            char                       ids[PN_IT_MAX_FILES_PER_PAGE][128];
            char                       names[PN_IT_MAX_FILES_PER_PAGE][128];
            uint32_t                   n_files = 0;
            uint32_t                   fi;
            pubnub_list_files_result_t lr;

            lopts.channel = e->a;
            lfut          = pubnub_list_files(ctx, &lopts);
            lst           = pubnub_await(lfut);

            if (PUBNUB_OK == lst) {
                lr = pubnub_list_files_result(lfut);
                for (fi = 0; fi < lr.count && n_files < PN_IT_MAX_FILES_PER_PAGE;
                     ++fi) {
                    pubnub_file_info_t inf;
                    size_t             cplen;

                    inf   = pubnub_list_files_result_file_at(lfut, fi);
                    cplen = inf.id.len < 127U ? inf.id.len : 127U;
                    memcpy(ids[n_files], inf.id.ptr, cplen);
                    ids[n_files][cplen] = '\0';
                    cplen = inf.name.len < 127U ? inf.name.len : 127U;
                    memcpy(names[n_files], inf.name.ptr, cplen);
                    names[n_files][cplen] = '\0';
                    ++n_files;
                }
            } else {
                print_message("cleanup list_delete_files: list failed: %s",
                              pubnub_res_str(lst));
            }
            pubnub_future_release(lfut);

            for (fi = 0; fi < n_files; ++fi) {
                pubnub_delete_file_opts_t dopts = PUBNUB_DELETE_FILE_OPTS_INIT;
                pubnub_future_t           dfut;
                pubnub_res_t              dst;

                dopts.channel   = e->a;
                dopts.file_id   = ids[fi];
                dopts.file_name = names[fi];
                dfut            = pubnub_delete_file(ctx, &dopts);
                dst             = pubnub_await(dfut);
                if (PUBNUB_OK != dst) {
                    print_message(
                        "cleanup list_delete_files: delete failed: %s",
                        pubnub_res_str(dst));
                }
                pubnub_future_release(dfut);
            }
        }
        break;
    }
    case IT_CLEANUP_REMOVE_CHANNEL_GROUP: {
        if (PUBNUB_ENABLE_CHANNEL_GROUPS) {
            pubnub_channel_group_remove_group_opts_t opts =
                PUBNUB_CHANNEL_GROUP_REMOVE_GROUP_OPTS_INIT;
            opts.channel_group = e->a;
            fut                = pubnub_channel_group_remove(ctx, &opts);
            dispatched         = 1;
        }
        break;
    }
    case IT_CLEANUP_REMOVE_UUID_METADATA: {
        if (PUBNUB_ENABLE_APP_CONTEXT) {
            pubnub_remove_uuid_metadata_opts_t opts =
                PUBNUB_REMOVE_UUID_METADATA_OPTS_INIT;
            opts.uuid  = e->a;
            fut        = pubnub_remove_uuid_metadata(ctx, &opts);
            dispatched = 1;
        }
        break;
    }
    case IT_CLEANUP_REMOVE_CHANNEL_METADATA: {
        if (PUBNUB_ENABLE_APP_CONTEXT) {
            pubnub_remove_channel_metadata_opts_t opts =
                PUBNUB_REMOVE_CHANNEL_METADATA_OPTS_INIT;
            opts.channel = e->a;
            fut          = pubnub_remove_channel_metadata(ctx, &opts);
            dispatched   = 1;
        }
        break;
    }
    case IT_CLEANUP_REMOVE_MEMBERS: {
        if (PUBNUB_ENABLE_APP_CONTEXT) {
            pubnub_member_input_t             rm = {.uuid_id = e->b};
            pubnub_set_channel_members_opts_t opts =
                PUBNUB_SET_CHANNEL_MEMBERS_OPTS_INIT;
            opts.channel      = e->a;
            opts.remove       = &rm;
            opts.remove_count = 1U;
            fut               = pubnub_set_channel_members(ctx, &opts);
            dispatched        = 1;
        }
        break;
    }
    case IT_CLEANUP_REMOVE_MEMBERSHIPS: {
        if (PUBNUB_ENABLE_APP_CONTEXT) {
            pubnub_membership_input_t rm = {.channel_id = e->b};
            pubnub_set_memberships_opts_t opts = PUBNUB_SET_MEMBERSHIPS_OPTS_INIT;
            opts.uuid         = e->a;
            opts.remove       = &rm;
            opts.remove_count = 1U;
            fut               = pubnub_set_memberships(ctx, &opts);
            dispatched        = 1;
        }
        break;
    }
    case IT_CLEANUP_REMOVE_PUSH_DEVICE: {
        if (PUBNUB_ENABLE_PUSH_NOTIFICATIONS) {
            pubnub_push_remove_device_opts_t opts =
                PUBNUB_PUSH_REMOVE_DEVICE_OPTS_INIT;
            opts.device = e->a;
            if ('\0' != e->b[0]) {
                /* b holds the APNS2 topic; non-empty means APNS2. */
                opts.gateway = PUBNUB_PUSH_APNS2;
                opts.topic   = e->b;
            } else {
                opts.gateway = PUBNUB_PUSH_FCM;
            }
            fut        = pubnub_push_remove_device(ctx, &opts);
            dispatched = 1;
        }
        break;
    }
    default: break;
    }

    if (dispatched) {
        st = pubnub_await(fut);
        if (PUBNUB_OK != st) {
            print_message("cleanup %s failed: %s",
                          it_cleanup_kind_str(e->kind),
                          pubnub_res_str(st));
        }
        pubnub_future_release(fut);
    }
}

void it_cleanup_add(it_cleanup_t*     cl,
                    it_cleanup_kind_t kind,
                    const char*       a,
                    const char*       b)
{
    it_cleanup_entry_t* e;

    if (NULL == cl || cl->count >= 64) {
        return;
    }
    e       = &cl->entries[cl->count];
    e->kind = kind;
    if (NULL != a) {
        pn_strlcpy(e->a, a, sizeof(e->a));
    } else {
        e->a[0] = '\0';
    }
    if (NULL != b) {
        pn_strlcpy(e->b, b, sizeof(e->b));
    } else {
        e->b[0] = '\0';
    }
    cl->count += 1;
}

void it_cleanup_run(it_cleanup_t* cl, pubnub_context_t* ctx)
{
    int i;

    if (NULL == cl || NULL == ctx) {
        return;
    }
    for (i = cl->count - 1; i >= 0; --i) {
        it_cleanup_run_entry(ctx, &cl->entries[i]);
    }
    cl->count = 0;
}
