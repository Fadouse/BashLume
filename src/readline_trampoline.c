/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stddef.h>
#include <stdint.h>

typedef int rl_command_func_t(int, int);
typedef int rl_hook_func_t(void);
typedef void rl_redisplay_func_t(void);

struct bashlume_event_context {
    size_t ownership;
    int previous_timeout;
    int installed_timeout;
};

extern rl_command_func_t *rl_last_func;
extern int rl_ding(void);
extern rl_command_func_t *bashlume_prepare_action(
    int action, int count, int key, int *status, int *prefetch_space,
    int *unbound);
extern rl_command_func_t *bashlume_prepare_space_prefetch(
    int count, int key, int *status, int *prefetch_space, int *unbound);
extern void bashlume_finish_space_prefetch(void);
extern rl_redisplay_func_t *bashlume_prepare_redisplay(void);
extern void bashlume_finish_redisplay(void);
extern rl_hook_func_t *bashlume_prepare_startup(void);
extern void bashlume_finish_startup(void);
extern rl_hook_func_t *bashlume_prepare_event(struct bashlume_event_context *context);
extern int bashlume_finish_event(
    const struct bashlume_event_context *context, int status, int *redraw);
extern int rl_forced_update_display(void);

static rl_command_func_t *bashlume_logical_wrapper;
static rl_command_func_t *bashlume_logical_fallback;

static void bashlume_normalize_last_function(void)
{
    if (bashlume_logical_wrapper != NULL &&
        rl_last_func == bashlume_logical_wrapper)
        rl_last_func = bashlume_logical_fallback;
    if (rl_last_func != bashlume_logical_wrapper) {
        bashlume_logical_wrapper = NULL;
        bashlume_logical_fallback = NULL;
    }
}

static int bashlume_dispatch_action(
    int action, rl_command_func_t *wrapper, int count, int key)
{
    int status = 0;
    int prefetch_space = 0;
    int unbound = 0;
    bashlume_normalize_last_function();
    rl_command_func_t *previous = rl_last_func;
    rl_command_func_t *fallback = bashlume_prepare_action(
        action, count, key, &status, &prefetch_space, &unbound);
    if (fallback != NULL) {
        bashlume_logical_wrapper = wrapper;
        bashlume_logical_fallback = fallback;
        status = fallback(count, key);
    } else if (unbound) {
        bashlume_logical_wrapper = wrapper;
        bashlume_logical_fallback = previous;
        status = rl_ding();
    } else {
        bashlume_logical_wrapper = NULL;
        bashlume_logical_fallback = NULL;
    }
    if (prefetch_space)
        bashlume_finish_space_prefetch();
    return status;
}

#define BASHLUME_ACTION(name, action) \
    int name(int count, int key)       \
    {                                  \
        return bashlume_dispatch_action(action, name, count, key); \
    }

BASHLUME_ACTION(bashlume_complete_forward_trampoline, 0)
BASHLUME_ACTION(bashlume_complete_backward_trampoline, 1)
BASHLUME_ACTION(bashlume_accept_all_trampoline, 2)
BASHLUME_ACTION(bashlume_accept_word_trampoline, 3)
BASHLUME_ACTION(bashlume_end_or_accept_trampoline, 4)
BASHLUME_ACTION(bashlume_enter_trampoline, 5)
BASHLUME_ACTION(bashlume_operate_and_get_next_trampoline, 6)
BASHLUME_ACTION(bashlume_cancel_trampoline, 8)

int bashlume_insert_space_and_prefetch_trampoline(int count, int key)
{
    int status = 0;
    int prefetch_space = 0;
    int unbound = 0;
    bashlume_normalize_last_function();
    rl_command_func_t *previous = rl_last_func;
    rl_command_func_t *fallback = bashlume_prepare_space_prefetch(
        count, key, &status, &prefetch_space, &unbound);
    if (fallback != NULL) {
        bashlume_logical_wrapper = bashlume_insert_space_and_prefetch_trampoline;
        bashlume_logical_fallback = fallback;
        status = fallback(count, key);
    } else if (unbound) {
        bashlume_logical_wrapper = bashlume_insert_space_and_prefetch_trampoline;
        bashlume_logical_fallback = previous;
        status = rl_ding();
    } else {
        bashlume_logical_wrapper = NULL;
        bashlume_logical_fallback = NULL;
    }
    if (prefetch_space)
        bashlume_finish_space_prefetch();
    return status;
}

void bashlume_redisplay_trampoline(void)
{
    bashlume_normalize_last_function();
    rl_redisplay_func_t *original = bashlume_prepare_redisplay();
    if (original != NULL)
        original();
    bashlume_finish_redisplay();
}

int bashlume_startup_trampoline(void)
{
    int status = 0;
    bashlume_normalize_last_function();
    rl_hook_func_t *original = bashlume_prepare_startup();
    if (original != NULL)
        status = original();
    bashlume_finish_startup();
    return status;
}

int bashlume_event_trampoline(void)
{
    bashlume_normalize_last_function();
    struct bashlume_event_context context = {0, -1, -1};
    int status = 0;
    int redraw = 0;
    rl_hook_func_t *original = bashlume_prepare_event(&context);
    if (original != NULL)
        status = original();
    status = bashlume_finish_event(&context, status, &redraw);
    if (redraw)
        rl_forced_update_display();
    return status;
}
