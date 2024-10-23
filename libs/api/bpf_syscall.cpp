// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#include "api_internal.h"
#include "bpf.h"
#include "libbpf.h"
#include "libbpf_internal.h"
#include "linux/bpf.h"

#include <windows.h>
#include <WinError.h>
#include <linux/bpf.h>
#include <stdexcept>

template <typename T> class ExtensibleStruct
{
  private:
    void* _orig;
    size_t _orig_size;
    T _tmp;
    T* _p;

    static void
    check_tail(const void* buf, size_t start, size_t end)
    {
        const unsigned char* p = (const unsigned char*)buf + start;
        const unsigned char* e = (const unsigned char*)buf + end;

        for (; p < e; p++) {
            if ((*p) != 0) {
                throw std::runtime_error("Non-zero tail");
            }
        }
    }

  public:
    ExtensibleStruct(void* ptr, size_t ptr_size) : _orig(ptr)
    {
        if (ptr_size >= sizeof(T)) {
            // Forward compatibility: allow a larger input as long as the
            // unknown fields are all zero.
            check_tail(ptr, sizeof(T), ptr_size);
            _orig_size = 0;
            _p = (T*)ptr;
        } else {
            // Backwards compatibility: allow a smaller input by implicitly zeroing all
            // missing fields.
            memcpy(&_tmp, ptr, ptr_size);
            _orig_size = ptr_size;
            _p = &_tmp;
        }
    }

    ~ExtensibleStruct() { memcpy(_orig, &_tmp, _orig_size); }

    T*
    operator->()
    {
        return _p;
    }

    T*
    operator&()
    {
        return _p;
    }

    T
    operator*()
    {
        return *_p;
    }
};

static bool
is_valid_obj_name(const char* p, const char** name)
{
    switch (strnlen(p, SYS_BPF_OBJ_NAME_LEN)) {
    case 0:
        *name = nullptr;
        return true;

    case SYS_BPF_OBJ_NAME_LEN:
        return false;

    default:
        *name = p;
        return true;
    }
}

static void
convert_to_map_info(struct bpf_map_info* bpf, const sys_bpf_map_info_t* sys);
static void
convert_to_sys_map_info(sys_bpf_map_info_t* sys, const struct bpf_map_info* bpf);
static void
convert_to_prog_info(struct bpf_prog_info* bpf, const sys_bpf_prog_info_t* sys);
static void
convert_to_sys_prog_info(sys_bpf_prog_info_t* sys, const struct bpf_prog_info* bpf);
static void
convert_to_link_info(struct bpf_link_info* bpf, const sys_bpf_link_info_t* sys);
static void
convert_to_sys_link_info(sys_bpf_link_info_t* sys, const struct bpf_link_info* bpf);

static int
obj_get_info_by_fd(sys_bpf_obj_info_attr_t* attr)
{
    union
    {
        struct bpf_map_info map;
        struct bpf_prog_info prog;
        struct bpf_link_info link;
    } tmp = {};
    uint32_t info_size = sizeof(tmp);
    ebpf_object_type_t type;

    ebpf_result_t result = ebpf_object_get_info_by_fd((fd_t)attr->bpf_fd, &tmp, &info_size, &type);
    if (result != EBPF_SUCCESS) {
        return libbpf_result_err(result);
    }

    switch (type) {
    case EBPF_OBJECT_MAP: {
        ExtensibleStruct<sys_bpf_map_info_t> info((void*)attr->info, (size_t)attr->info_len);

        convert_to_map_info(&tmp.map, &info);

        info_size = sizeof(tmp.map);
        result = ebpf_object_get_info_by_fd((fd_t)attr->bpf_fd, &tmp.map, &info_size, NULL);
        if (result != EBPF_SUCCESS) {
            return libbpf_result_err(result);
        }

        convert_to_sys_map_info(&info, &tmp.map);
        return 0;
    }

    case EBPF_OBJECT_PROGRAM: {
        ExtensibleStruct<sys_bpf_prog_info_t> info((void*)attr->info, (size_t)attr->info_len);
        sys_bpf_prog_info_t* sys = &info;

        if (sys->jited_prog_len != 0 || sys->xlated_prog_len != 0 || sys->jited_prog_insns != 0 ||
            sys->xlated_prog_insns != 0) {
            return -EINVAL;
        }

        convert_to_prog_info(&tmp.prog, &info);

        info_size = sizeof(tmp.prog);
        result = ebpf_object_get_info_by_fd((fd_t)attr->bpf_fd, &tmp.prog, &info_size, NULL);
        if (result != EBPF_SUCCESS) {
            return libbpf_result_err(result);
        }

        convert_to_sys_prog_info(&info, &tmp.prog);
        return 0;
    }

    case EBPF_OBJECT_LINK: {
        ExtensibleStruct<sys_bpf_link_info_t> info((void*)attr->info, (size_t)attr->info_len);

        convert_to_link_info(&tmp.link, &info);

        info_size = sizeof(tmp.link);
        result = ebpf_object_get_info_by_fd((fd_t)attr->bpf_fd, &tmp.link, &info_size, NULL);
        if (result != EBPF_SUCCESS) {
            return libbpf_result_err(result);
        }

        convert_to_sys_link_info(&info, &tmp.link);
        return 0;
    }

    default:
        return -EINVAL;
    }
}

int
bpf(int cmd, union bpf_attr* p, unsigned int size)
{
    // bpf() is ABI compatible with the Linux bpf() syscall.
    //
    // * Do not return errors via errno.
    // * Do not assume that bpf_attr has a particular size.

    try {
        switch (cmd) {
        case BPF_LINK_DETACH: {
            ExtensibleStruct<sys_bpf_link_detach_attr_t> attr((void*)p, (size_t)size);
            return bpf_link_detach(attr->link_fd);
        }
        case BPF_LINK_GET_FD_BY_ID: {
            ExtensibleStruct<uint32_t> link_id((void*)p, (size_t)size);
            return bpf_link_get_fd_by_id(*link_id);
        }
        case BPF_LINK_GET_NEXT_ID: {
            ExtensibleStruct<sys_bpf_map_next_id_attr_t> attr((void*)p, (size_t)size);
            return bpf_link_get_next_id(attr->start_id, &attr->next_id);
        }
        case BPF_MAP_CREATE: {
            ExtensibleStruct<sys_bpf_map_create_attr_t> attr((void*)p, (size_t)size);
            struct bpf_map_create_opts opts = {
                .inner_map_fd = attr->inner_map_fd,
                .map_flags = attr->map_flags,
                .numa_node = attr->numa_node,
                .map_ifindex = attr->map_ifindex,
            };
            const char* name = nullptr;

            if (!is_valid_obj_name(attr->map_name, &name)) {
                return -EINVAL;
            }

            return bpf_map_create(attr->map_type, name, attr->key_size, attr->value_size, attr->max_entries, &opts);
        }
        case BPF_MAP_DELETE_ELEM: {
            ExtensibleStruct<sys_bpf_map_delete_attr_t> attr((void*)p, (size_t)size);
            return bpf_map_delete_elem(attr->map_fd, (const void*)attr->key);
        }
        case BPF_MAP_GET_FD_BY_ID: {
            ExtensibleStruct<uint32_t> map_id((void*)p, (size_t)size);
            return bpf_map_get_fd_by_id(*map_id);
        }
        case BPF_MAP_GET_NEXT_ID: {
            ExtensibleStruct<sys_bpf_map_next_id_attr_t> attr((void*)p, (size_t)size);
            return bpf_map_get_next_id(attr->start_id, &attr->next_id);
        }
        case BPF_MAP_GET_NEXT_KEY: {
            ExtensibleStruct<sys_bpf_map_next_key_attr_t> attr((void*)p, (size_t)size);
            return bpf_map_get_next_key(attr->map_fd, (const void*)attr->key, (void*)attr->next_key);
        }
        case BPF_MAP_LOOKUP_ELEM: {
            ExtensibleStruct<sys_bpf_map_lookup_attr_t> attr((void*)p, (size_t)size);

            if (attr->flags != 0) {
                return -EINVAL;
            }

            return bpf_map_lookup_elem(attr->map_fd, (const void*)attr->key, (void*)attr->value);
        }
        case BPF_MAP_LOOKUP_AND_DELETE_ELEM: {
            ExtensibleStruct<sys_bpf_map_lookup_attr_t> attr((void*)p, (size_t)size);

            if (attr->flags != 0) {
                return -EINVAL;
            }

            return bpf_map_lookup_and_delete_elem(attr->map_fd, (const void*)attr->key, (void*)attr->value);
        }
        case BPF_MAP_UPDATE_ELEM: {
            ExtensibleStruct<sys_bpf_map_lookup_attr_t> attr((void*)p, (size_t)size);
            return bpf_map_update_elem(attr->map_fd, (const void*)attr->key, (const void*)attr->value, attr->flags);
        }
        case BPF_OBJ_GET: {
            ExtensibleStruct<sys_bpf_obj_pin_attr_t> attr((void*)p, (size_t)size);
            if (attr->bpf_fd != 0 || attr->flags != 0) {
                return -EINVAL;
            }
            return bpf_obj_get((const char*)attr->pathname);
        }
        case BPF_PROG_ATTACH: {
            ExtensibleStruct<sys_bpf_prog_attach_attr_t> attr((void*)p, (size_t)size);
            return bpf_prog_attach(attr->attach_bpf_fd, attr->target_fd, attr->attach_type, attr->attach_flags);
        }
        case BPF_PROG_DETACH: {
            ExtensibleStruct<sys_bpf_prog_attach_attr_t> attr((void*)p, (size_t)size);
            return bpf_prog_detach(attr->target_fd, attr->attach_type);
        }
        case BPF_OBJ_GET_INFO_BY_FD: {
            ExtensibleStruct<sys_bpf_obj_info_attr_t> attr((void*)p, (size_t)size);
            return obj_get_info_by_fd(&attr);
        }
        case BPF_OBJ_PIN: {
            ExtensibleStruct<sys_bpf_obj_pin_attr_t> attr((void*)p, (size_t)size);

            if (attr->flags != 0) {
                return -EINVAL;
            }

            return bpf_obj_pin(attr->bpf_fd, (const char*)attr->pathname);
        }
        case BPF_PROG_BIND_MAP: {
            ExtensibleStruct<sys_bpf_prog_bind_map_attr_t> attr((void*)p, (size_t)size);
            struct bpf_prog_bind_opts opts = {sizeof(struct bpf_prog_bind_opts), attr->flags};
            return bpf_prog_bind_map(attr->prog_fd, attr->map_fd, &opts);
        }
        case BPF_PROG_GET_FD_BY_ID: {
            ExtensibleStruct<uint32_t> prog_id((void*)p, (size_t)size);
            return bpf_prog_get_fd_by_id(*prog_id);
        }
        case BPF_PROG_GET_NEXT_ID: {
            ExtensibleStruct<sys_bpf_map_next_id_attr_t> attr((void*)p, (size_t)size);
            return bpf_prog_get_next_id(attr->start_id, &attr->next_id);
        }
        case BPF_PROG_LOAD: {
            ExtensibleStruct<sys_bpf_prog_load_attr_t> attr((void*)p, (size_t)size);

            if (attr->prog_flags != 0) {
                return -EINVAL;
            }

            struct bpf_prog_load_opts opts = {
                .prog_flags = attr->prog_flags,
                .kern_version = attr->kern_version,
                .log_size = attr->log_size,
                .log_buf = (char*)attr->log_buf,
            };
            const char* name = nullptr;

            if (!is_valid_obj_name(attr->prog_name, &name)) {
                return -EINVAL;
            }

            if (name == nullptr) {
                // Disable using sha256 as object name.
                name = "";
            }

            return bpf_prog_load(
                attr->prog_type,
                name,
                (const char*)attr->license,
                (const struct bpf_insn*)attr->insns,
                attr->insn_cnt,
                &opts);
        }
        case BPF_PROG_TEST_RUN: {
            ExtensibleStruct<sys_bpf_prog_run_attr_t> attr((void*)p, (size_t)size);

            if (attr->_pad0 != 0) {
                return -EINVAL;
            }

            bpf_test_run_opts test_run_opts = {
                .sz = sizeof(bpf_test_run_opts),
                .data_in = (void*)attr->data_in,
                .data_out = (void*)attr->data_out,
                .data_size_in = attr->data_size_in,
                .data_size_out = attr->data_size_out,
                .ctx_in = (void*)attr->ctx_in,
                .ctx_out = (void*)attr->ctx_out,
                .ctx_size_in = attr->ctx_size_in,
                .ctx_size_out = attr->ctx_size_out,
                .repeat = (int)(attr->repeat),
                .flags = attr->flags,
                .cpu = attr->cpu,
                .batch_size = attr->batch_size,
            };

            int retval = bpf_prog_test_run_opts(attr->prog_fd, &test_run_opts);
            if (retval == 0) {
                attr->data_size_out = test_run_opts.data_size_out;
                attr->ctx_size_out = test_run_opts.ctx_size_out;
                attr->retval = test_run_opts.retval;
                attr->duration = test_run_opts.duration;
            }

            return retval;
        }
        default:
            SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
            return -EINVAL;
        }
    } catch (...) {
        return -EINVAL;
    }
}

#define BPF_TO_SYS(field) sys->field = bpf->field
#define BPF_TO_SYS_STR(field) strncpy_s(sys->field, sizeof(sys->field), bpf->field, _TRUNCATE)
#define BPF_TO_SYS_MEM(field) memcpy(sys->field, bpf->field, sizeof(sys->field))
#define SYS_TO_BPF(field) bpf->field = sys->field
#define SYS_TO_BPF_STR(field) strncpy_s(bpf->field, sys->field, sizeof(bpf->field))
#define SYS_TO_BPF_MEM(field) memcpy(bpf->field, sys->field, sizeof(bpf->field))

static void
convert_to_map_info(struct bpf_map_info* bpf, const sys_bpf_map_info_t* sys)
{
    SYS_TO_BPF(type);
    SYS_TO_BPF(id);
    SYS_TO_BPF(key_size);
    SYS_TO_BPF(value_size);
    SYS_TO_BPF(max_entries);
    SYS_TO_BPF(map_flags);
    SYS_TO_BPF_STR(name);
}

static void
convert_to_sys_map_info(sys_bpf_map_info_t* sys, const struct bpf_map_info* bpf)
{
    BPF_TO_SYS(type);
    BPF_TO_SYS(id);
    BPF_TO_SYS(key_size);
    BPF_TO_SYS(value_size);
    BPF_TO_SYS(max_entries);
    BPF_TO_SYS(map_flags);
    BPF_TO_SYS_STR(name);
}

static void
convert_to_prog_info(struct bpf_prog_info* bpf, const sys_bpf_prog_info_t* sys)
{
    SYS_TO_BPF(type);
    SYS_TO_BPF(id);
    // SYS_TO_BPF_MEM(tag);
    // SYS_TO_BPF(jited_prog_len);
    // SYS_TO_BPF(xlated_prog_len);
    // SYS_TO_BPF(jited_prog_insns);
    // SYS_TO_BPF(xlated_prog_insns);
    // SYS_TO_BPF(load_time);
    // SYS_TO_BPF(created_by_uid);
    SYS_TO_BPF(nr_map_ids);
    SYS_TO_BPF(map_ids);
    SYS_TO_BPF_STR(name);
}

static void
convert_to_sys_prog_info(sys_bpf_prog_info_t* sys, const struct bpf_prog_info* bpf)
{
    BPF_TO_SYS(type);
    BPF_TO_SYS(id);
    // BPF_TO_SYS_MEM(tag);
    // BPF_TO_SYS(jited_prog_len);
    // BPF_TO_SYS(xlated_prog_len);
    // BPF_TO_SYS(jited_prog_insns);
    // BPF_TO_SYS(xlated_prog_insns);
    // BPF_TO_SYS(load_time);
    // BPF_TO_SYS(created_by_uid);
    BPF_TO_SYS(nr_map_ids);
    BPF_TO_SYS(map_ids);
    BPF_TO_SYS_STR(name);
}

static void
convert_to_link_info(struct bpf_link_info* bpf, const sys_bpf_link_info_t* sys)
{
    SYS_TO_BPF(type);
    SYS_TO_BPF(id);
    SYS_TO_BPF(prog_id);
}

static void
convert_to_sys_link_info(sys_bpf_link_info_t* sys, const struct bpf_link_info* bpf)
{
    BPF_TO_SYS(type);
    BPF_TO_SYS(id);
    BPF_TO_SYS(prog_id);
}
