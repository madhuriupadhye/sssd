AC_SUBST(GSSAPI_KRB5_CFLAGS)
AC_SUBST(GSSAPI_KRB5_LIBS)

PKG_CHECK_MODULES(GSSAPI_KRB5,
    krb5-gssapi,
    ,
    AC_MSG_ERROR("Please install krb5-devel")
    )
