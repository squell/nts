#include <sys/uio.h>
#include <assert.h>
inline void iovec_inc_many(struct iovec *x, int _ignore, size_t n)
{
    assert(_ignore == 1);
    assert(n <= x->iov_len);
    x->iov_len -= n;
    x->iov_base += n;
}
