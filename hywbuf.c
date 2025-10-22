// hywbuf.c
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>

#define BUFFER_COMPAT_FACTOR (2)
#define BUFFER_LINEAR_GROWTH_THRESHOLD (4096)
#define BUFFER_LINEAR_GROWTH_SIZE (4096)

// #define DEBUG_MEM_GROW
// #define DEBUG_OP_TIME
#ifdef DEBUG_OP_TIME
static inline double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return ts.tv_sec * 1e9 + ts.tv_nsec;
}
#define TIME_SECTION(name, code_block) \
    do { \
        double t0 = now_ns(); \
        code_block; \
        double t1 = now_ns(); \
        printf("[DEBUG][%s] %.3f µs\n", name, (t1 - t0)/1000.0); \
    } while(0)
#endif


typedef struct {
    char* data;
    size_t len;
    size_t read_pos;
    size_t write_pos;
    size_t compat_factor;
    size_t linear_growth_threshold;
    size_t linear_growth_size;
} buffer_t;

typedef struct {
    PyObject_HEAD
    buffer_t* buf;
} PyBufferObject;

static void ensure_freespace(buffer_t* b, size_t n);
static void grow(buffer_t* b, size_t needed);
static int try_compat(buffer_t* b);
static void compat(buffer_t* b);
static char* actual_data(buffer_t* b);
static char* free_space(buffer_t* b);
static size_t adjust_size_to_2powN(size_t n);

static void buffer_set(buffer_t* b, size_t factor, size_t gsize, size_t threshold) {
    b->compat_factor = factor;
    b->linear_growth_size = adjust_size_to_2powN(gsize);
    b->linear_growth_threshold = adjust_size_to_2powN(threshold);
}
static buffer_t* buffer_new_internal(size_t len) {
    if (len == 0) len = 1;
    len = adjust_size_to_2powN(len);
    buffer_t* b = malloc(sizeof(buffer_t));
    if (!b) return NULL;
    b->data = malloc(len);
    if (!b->data) {
        free(b);
        return NULL;
    }
    b->len = len;
    b->read_pos = b->write_pos = 0;
    // default settings
    buffer_set(b, BUFFER_COMPAT_FACTOR, BUFFER_LINEAR_GROWTH_SIZE, BUFFER_LINEAR_GROWTH_THRESHOLD);
    return b;
}
static void buffer_free_internal(buffer_t* b) {
    if (!b) return;
    free(b->data);
    free(b);
}

static char* actual_data(buffer_t* b) {return b->data + b->read_pos; }
static char* free_space(buffer_t* b) { return b->data + b->write_pos; }
// adjust size to 1,2,4,8,16,...,2^N
static size_t adjust_size_to_2powN(size_t n) {
    if (n == 0) return 1;
    n -= 1;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    if (sizeof(size_t) > 4)
        n |= n >> 32;
    return n + 1;
}
static size_t buffer_datasiz(buffer_t* b) { return b->write_pos - b->read_pos; }
static size_t buffer_freespace(buffer_t* b) { return b->len - b->write_pos; }

static void compat(buffer_t* b) {
    size_t datasiz = buffer_datasiz(b);
    memmove(b->data, actual_data(b), datasiz);
    b->read_pos = 0;
    b->write_pos = datasiz;
}

static int try_compat(buffer_t* b) {
    if (b->read_pos > b->len / b->compat_factor) {
        compat(b);
        return 1;
    }
    return 0;
}

static void grow(buffer_t* b, size_t needed) {
    if (needed == 0) return;
    size_t new_len = b->len + needed;
#ifdef DEBUG_MEM_GROW
    printf("[Debug] want to grow to: %zu, now: %zu\n", new_len, b->len);
#endif
    if (new_len <= b->linear_growth_threshold)
        new_len = adjust_size_to_2powN(new_len);
    else
        new_len = b->linear_growth_threshold +
        (((new_len - b->linear_growth_threshold + b->linear_growth_size - 1)
            / b->linear_growth_size) * b->linear_growth_size);
    char* new_data = malloc(new_len);
    if (!new_data) return;
    size_t datasiz = buffer_datasiz(b);
    memcpy(new_data, actual_data(b), datasiz);
    free(b->data);
    b->data = new_data;
    b->len = new_len;
    b->read_pos = 0;
    b->write_pos = datasiz;
#ifdef DEBUG_MEM_GROW
    printf("[Debug] buffer length after growth: %zu\n", b->len);
#endif
}

static void ensure_freespace(buffer_t* b, size_t n) {
    if (buffer_freespace(b) >= n) return;
    try_compat(b);
    size_t fs = buffer_freespace(b);
    if (fs >= n) return;
    size_t needed = n - fs;
    grow(b, needed);
}


static int PyBuffer_init(PyBufferObject* self, PyObject* args, PyObject* kwds) {
    Py_ssize_t len = 0;
    if (!PyArg_ParseTuple(args, "|n", &len)) return -1;
    self->buf = buffer_new_internal((size_t)len);
    if (!self->buf) {
        PyErr_SetString(PyExc_MemoryError, "Failed to allocate buffer");
        return -1;
    }
    return 0;
}

static void PyBuffer_dealloc(PyBufferObject* self) {
    buffer_free_internal(self->buf);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject* PyBuffer_set(PyBufferObject* self, PyObject* args) {
    Py_ssize_t factor = BUFFER_COMPAT_FACTOR;
    Py_ssize_t gsize = BUFFER_LINEAR_GROWTH_SIZE;
    Py_ssize_t threshold = BUFFER_LINEAR_GROWTH_THRESHOLD;
    if (!PyArg_ParseTuple(args, "|nnn", &factor, &gsize, &threshold)) {
        return NULL;
    }
    if (factor < 1) {
        PyErr_SetString(PyExc_ValueError, "compat factor must be at least 1");
        return NULL;
    }
    if (gsize <= 0) {
        PyErr_SetString(PyExc_ValueError, "linear growth size must be positive");
        return NULL;
    }
    if (threshold <= 0) {
        PyErr_SetString(PyExc_ValueError, "linear growth threshold must be positive");
        return NULL;
    }
    buffer_set(self->buf, (size_t)factor, (size_t)gsize, (size_t)threshold);
    Py_RETURN_NONE;
}

static PyObject* PyBuffer_write(PyBufferObject* self, PyObject* args) {
    const char* data;
    Py_ssize_t len;
#ifdef DEBUG_OP_TIME
TIME_SECTION("PyBuffer_write_python_parse", {
#endif
    if (!PyArg_ParseTuple(args, "y#", &data, &len))
        return NULL;
#ifdef DEBUG_OP_TIME
});
#endif
#ifdef DEBUG_OP_TIME
TIME_SECTION("PyBuffer_write_my_logic", {
#endif
    ensure_freespace(self->buf, len);
    memcpy(free_space(self->buf), data, len);
    self->buf->write_pos += len;
#ifdef DEBUG_OP_TIME
});
#endif
    Py_RETURN_NONE;
}

static PyObject* PyBuffer_read(PyBufferObject* self, PyObject* args) {
    Py_ssize_t n;
#ifdef DEBUG_OP_TIME
TIME_SECTION("PyBuffer_read_python_parse", {
#endif
    if (!PyArg_ParseTuple(args, "n", &n))
        return NULL;
#ifdef DEBUG_OP_TIME
});
#endif

#ifdef DEBUG_OP_TIME
TIME_SECTION("PyBuffer_read_my_logic", {
#endif
    size_t datasiz = buffer_datasiz(self->buf);
    if ((size_t)n > datasiz)
        n = datasiz;
#ifdef DEBUG_OP_TIME
});
#endif
#ifdef DEBUG_OP_TIME
TIME_SECTION("PyBuffer_return_pybytes", {
#endif
    PyObject* result = PyBytes_FromStringAndSize(actual_data(self->buf), n);
#ifdef DEBUG_OP_TIME
})
#endif
    self->buf->read_pos += n;
    if (self->buf->read_pos == self->buf->write_pos)
        self->buf->read_pos = self->buf->write_pos = 0;
    return result;
}

static PyObject* PyBuffer_datasiz(PyBufferObject* self, PyObject* Py_UNUSED(ignored)) {
    return PyLong_FromSize_t(buffer_datasiz(self->buf));
}

static PyObject* PyBuffer_reset(PyBufferObject* self, PyObject* Py_UNUSED(ignored)) {
    self->buf->read_pos = self->buf->write_pos = 0;
    Py_RETURN_NONE;
}

static PyObject* PyBuffer_read_from_fd(PyBufferObject* self, PyObject* args) {
    int fd;
    Py_ssize_t nbytes;
    if (!PyArg_ParseTuple(args, "in", &fd, &nbytes))
        return NULL;
    if (nbytes <= 0) {
        PyErr_SetString(PyExc_ValueError, "read bytes must be positive");
        return NULL;
    }
    size_t total_read = 0;
    while ((Py_ssize_t)total_read < nbytes) {
        size_t to_read = (size_t)(nbytes - total_read);
        ensure_freespace(self->buf, to_read);
        ssize_t ret = read(fd, free_space(self->buf), to_read);
        if (ret == 0) {
            break;
        } else if (ret < 0) {
            if (errno == EINTR)
                continue;
            PyErr_SetFromErrno(PyExc_OSError); // error or nonblocking fd
            return NULL;
        }
        self->buf->write_pos += (size_t)ret;
        total_read += (size_t)ret;
        if ((size_t)ret < to_read)
            break;
    }
    return PyLong_FromSize_t(total_read);
}

static PyObject* PyBuffer_write_to_fd(PyBufferObject* self, PyObject* args) {
    int fd;
    Py_ssize_t nbytes;
    if (!PyArg_ParseTuple(args, "in", &fd, &nbytes))
        return NULL;
    size_t datasiz = buffer_datasiz(self->buf);
    if ((size_t)nbytes > datasiz)
        nbytes = datasiz;
    size_t total_written = 0;
    while ((Py_ssize_t)total_written < nbytes) {
        size_t to_write = (size_t)(nbytes - total_written);
        ssize_t ret = write(fd, actual_data(self->buf) + total_written, to_write);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            PyErr_SetFromErrno(PyExc_OSError);
            return NULL;
        }
        if (ret == 0)
            break;
        total_written += (size_t)ret;
    }
    self->buf->read_pos += total_written;
    if (self->buf->read_pos == self->buf->write_pos)
        self->buf->read_pos = self->buf->write_pos = 0;
    return PyLong_FromSize_t(total_written);
}

static PyObject* PyBuffer_discard(PyBufferObject* self, PyObject* args) {
    Py_ssize_t n;
    if (!PyArg_ParseTuple(args, "n", &n)) return NULL;
    size_t datasiz = buffer_datasiz(self->buf);
    if ((size_t)n >= datasiz) self->buf->write_pos = self->buf->read_pos = 0;
    else self->buf->read_pos += n;
    Py_RETURN_NONE;
}

static PyMethodDef PyBuffer_methods[] = {
    {"set", (PyCFunction)PyBuffer_set, METH_VARARGS, "Set buffer parameters: compat_factor, linear_growth_size, linear_growth_threshold"},
    {"write", (PyCFunction)PyBuffer_write, METH_VARARGS, "Write bytes to buffer"},
    {"read", (PyCFunction)PyBuffer_read, METH_VARARGS, "Read bytes from buffer"},
    {"datasiz", (PyCFunction)PyBuffer_datasiz, METH_NOARGS, "Return data size"},
    {"reset", (PyCFunction)PyBuffer_reset, METH_NOARGS, "Reset buffer"},
    {"read_from_fd", (PyCFunction)PyBuffer_read_from_fd, METH_VARARGS, "Read bytes from fileno"},
    {"write_to_fd", (PyCFunction)PyBuffer_write_to_fd, METH_VARARGS, "Write bytes to fileno"},
    {"discard", (PyCFunction)PyBuffer_discard, METH_VARARGS, "Discard n bytes from the beginning of the buffer"},
    {NULL}
};

static PyTypeObject PyBufferType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "hywbuf.BytesBuffer",
    .tp_doc = "C-backed dynamic buffer",
    .tp_basicsize = sizeof(PyBufferObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyType_GenericNew,
    .tp_init = (initproc)PyBuffer_init,
    .tp_dealloc = (destructor)PyBuffer_dealloc,
    .tp_methods = PyBuffer_methods,
};

static PyModuleDef buffer_module = {
    PyModuleDef_HEAD_INIT,
    .m_name = "hywbuf",
    .m_doc = "C extension for dynamic buffer",
    .m_size = -1,
};

PyMODINIT_FUNC PyInit_hywbuf(void) {
    PyObject* m;
    if (PyType_Ready(&PyBufferType) < 0)
        return NULL;

    m = PyModule_Create(&buffer_module);
    if (!m)
        return NULL;

    Py_INCREF(&PyBufferType);
    PyModule_AddObject(m, "BytesBuffer", (PyObject*)&PyBufferType);
    return m;
}
