// SPDX-FileCopyrightText: 2013-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2013-2020 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2013-2020 sivaramaaa <sivaramaaa@gmail.com>
// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>
#include <string.h>

// Function prototypes api

RZ_API RZ_OWN RzCallableArg *rz_type_func_arg_new(RzTypeDB *typedb, RZ_NONNULL const char *name, RZ_NONNULL RzType *type) {
	rz_return_val_if_fail(typedb && name && type, NULL);
	RzCallableArg *arg = RZ_NEW0(RzCallableArg);
	if (!arg) {
		return NULL;
	}
	arg->name = strdup(name);
	arg->type = type;
	return arg;
}

RZ_API void rz_type_func_arg_free(RzCallableArg *arg) {
	if (arg->name) {
		free(arg);
	}
	rz_type_free(arg->type);
	free(arg);
}

RZ_API RZ_OWN RzCallable *rz_type_func_new(RzTypeDB *typedb, RZ_NONNULL const char *name, RZ_NULLABLE RzType *type) {
	rz_return_val_if_fail(typedb && name, NULL);
	RzCallable *callable = RZ_NEW0(RzCallable);
	if (!callable) {
		return NULL;
	}
	callable->name = strdup(name);
	callable->args = rz_pvector_new((RzPVectorFree)rz_type_func_arg_free);
	if (!type) {
		callable->ret = rz_type_new_default(typedb);
		if (!callable->ret) {
			return NULL;
		}
	} else {
		callable->ret = type;
	}
	return callable;
}

RZ_API void rz_type_callable_free(RZ_NONNULL RzCallable *callable) {
	free(callable->name);
	rz_type_free(callable->ret);
	rz_pvector_free(callable->args);
	free(callable);
}

/**
 * \brief Returns the RzCallable from the database by name
 *
 * \param typedb Type Database instance
 * \param func_name RzCallable (function) name to search
 */
RZ_API RZ_BORROW RzCallable *rz_type_func_get(RzTypeDB *typedb, RZ_NONNULL const char *func_name) {
	rz_return_val_if_fail(typedb && func_name, NULL);
	bool found = false;
	RzCallable *callable = ht_pp_find(typedb->callables, func_name, &found);
	if (!found || !callable) {
		eprintf("Cannot find function type \"%s\"\n", func_name);
		return NULL;
	}
	return callable;
}

/**
 * \brief Removes RzBaseType from the Types DB
 *
 * \param typedb Type Database instance
 * \param type RzBaseType to remove
 */
RZ_API bool rz_type_func_delete(RzTypeDB *typedb, RZ_NONNULL const char *func_name) {
	rz_return_val_if_fail(typedb && func_name, NULL);
	ht_pp_delete(typedb->callables, func_name);
	return true;
}

RZ_API bool rz_type_func_exist(RzTypeDB *typedb, RZ_NONNULL const char *func_name) {
	rz_return_val_if_fail(typedb && func_name, false);
	return rz_type_func_get(typedb, func_name) != NULL;
}

RZ_API RZ_BORROW RzType *rz_type_func_ret(RzTypeDB *typedb, const char *func_name) {
	rz_return_val_if_fail(typedb && func_name, NULL);
	RzCallable *callable = rz_type_func_get(typedb, func_name);
	if (!callable) {
		return NULL;
	}
	return callable->ret;
}

RZ_API RZ_BORROW const char *rz_type_func_cc(RzTypeDB *typedb, const char *func_name) {
	rz_return_val_if_fail(typedb && func_name, NULL);
	RzCallable *callable = rz_type_func_get(typedb, func_name);
	if (!callable) {
		return NULL;
	}
	return callable->cc;
}

RZ_API int rz_type_func_args_count(RzTypeDB *typedb, const char *func_name) {
	rz_return_val_if_fail(typedb && func_name, 0);
	RzCallable *callable = rz_type_func_get(typedb, func_name);
	if (!callable) {
		return -1;
	}
	return rz_pvector_len(callable->args);
}

RZ_API RZ_BORROW RzType *rz_type_func_args_type(RzTypeDB *typedb, RZ_NONNULL const char *func_name, int i) {
	rz_return_val_if_fail(typedb && func_name, NULL);
	RzCallable *callable = rz_type_func_get(typedb, func_name);
	if (!callable) {
		return NULL;
	}
	RzCallableArg *arg = rz_pvector_index_ptr(callable->args, i);
	if (!arg) {
		rz_warn_if_reached(); // should not happen in the types database
		return NULL;
	}
	return arg->type;
}

RZ_API RZ_BORROW const char *rz_type_func_args_name(RzTypeDB *typedb, RZ_NONNULL const char *func_name, int i) {
	rz_return_val_if_fail(typedb && func_name, NULL);
	RzCallable *callable = rz_type_func_get(typedb, func_name);
	if (!callable) {
		return NULL;
	}
	RzCallableArg *arg = rz_pvector_index_ptr(callable->args, i);
	if (!arg) {
		rz_warn_if_reached(); // should not happen in the types database
		return NULL;
	}
	return arg->name;
}

RZ_API bool rz_type_func_arg_add(RzTypeDB *typedb, RZ_NONNULL const char *func_name, RZ_NONNULL const char *arg_name, RZ_NONNULL RzType *arg_type) {
	rz_return_val_if_fail(typedb && func_name, NULL);
	RzCallable *callable = rz_type_func_get(typedb, func_name);
	if (!callable) {
		return false;
	}
	RzCallableArg *arg = rz_type_func_arg_new(typedb, arg_name, arg_type);
	if (!arg) {
		return false;
	}
	rz_pvector_push(callable->args, arg);
	return true;
}

RZ_API bool rz_type_func_ret_set(RzTypeDB *typedb, const char *func_name, RZ_NONNULL RzType *type) {
	rz_return_val_if_fail(typedb && func_name && type, NULL);
	RzCallable *callable = rz_type_func_get(typedb, func_name);
	if (!callable) {
		return false;
	}
	callable->ret = type;
	return true;
}

RZ_API bool rz_type_func_is_noreturn(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, false);
	RzCallable *callable = rz_type_func_get(typedb, name);
	if (!callable) {
		return NULL;
	}
	return callable->noret;
}

RZ_API bool rz_type_func_noreturn_add(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, false);
	// If the function exists with the specified name already, we set the noreturn flag for it
	RzCallable *callable = rz_type_func_get(typedb, name);
	if (callable) {
		callable->noret = true;
	} else {
		// If it doesn't - we create a new dummy RzCallable for it
		// The return type is default and no arguments
		callable = rz_type_func_new(typedb, name, NULL);
		if (!callable) {
			return false;
		}
	}
	return true;
}

RZ_API bool rz_type_func_noreturn_drop(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, false);
	RzCallable *callable = rz_type_func_get(typedb, name);
	if (!callable) {
		return false;
	}
	callable->noret = false;
	return true;
}

// Listing function types

static bool function_names_collect_cb(void *user, const void *k, const void *v) {
	RzList *l = (RzList *)user;
	RzCallable *callable = (RzCallable *)v;
	rz_list_append(l, strdup(callable->name));
	return true;
}

/**
 * \brief Returns the list of all function type names
 *
 * \param typedb Types Database instance
 */
RZ_API RZ_OWN RzList *rz_type_function_names(RzTypeDB *typedb) {
	rz_return_val_if_fail(typedb, NULL);
	RzList *result = rz_list_newf(free);
	ht_pp_foreach(typedb->callables, function_names_collect_cb, &result);
	return result;
}

static bool noreturn_function_names_collect_cb(void *user, const void *k, const void *v) {
	RzList *l = (RzList *)user;
	RzCallable *callable = (RzCallable *)v;
	if (callable->noret) {
		rz_list_append(l, strdup(callable->name));
	}
	return true;
}

/**
 * \brief Returns the list of all noreturn function type names
 *
 * \param typedb Types Database instance
 */
RZ_API RZ_OWN RzList *rz_type_noreturn_function_names(RzTypeDB *typedb) {
	rz_return_val_if_fail(typedb, NULL);
	RzList *noretl = rz_list_newf(free);
	ht_pp_foreach(typedb->callables, noreturn_function_names_collect_cb, &noretl);
	return noretl;
}

