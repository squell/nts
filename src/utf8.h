bool ascii_is_valid_n(const char *p, size_t len) {
    for(size_t i=0; i < len; i++) {
        if (!isascii(p[i]) || !isgraph(p[i]))
            return false;
    }
    return true;
}

