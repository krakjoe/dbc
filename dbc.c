/*
  +----------------------------------------------------------------------+
  | PHP Version 7                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2016 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author:                                                              |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "ext/spl/spl_exceptions.h"
#include "php_dbc.h"

#include "Zend/zend_extensions.h"

ZEND_DECLARE_MODULE_GLOBALS(dbc)

zend_extension zend_extension_entry;

static void php_dbc_destroy_contract(zval *zv) {
	//destroy_op_array((zend_op_array*)Z_PTR_P(zv));
	//zend_arena_release(&CG(arena), Z_PTR_P(zv));
}

static void php_dbc_recv_args(zend_op_array *contract, zend_op_array *active) {
	uint32_t it;

	for (it = 0; it < active->last; it++){
		switch (active->opcodes[it].opcode) {
			case ZEND_EXT_NOP:
			case ZEND_EXT_STMT:
			case ZEND_NOP:
				continue;

			case ZEND_RECV_INIT:
			case ZEND_RECV:
				if (contract->opcodes) {
					contract->opcodes = 
						(zend_op*) erealloc(
							contract->opcodes, 
								sizeof(zend_op) * ++contract->last);
				} else {
					contract->opcodes = 
						(zend_op*) ecalloc(sizeof(zend_op), ++contract->last);
				}
				memcpy(&contract->opcodes[contract->last - 1], &active->opcodes[it], sizeof(zend_op));
			break;

			default:
				return;
		}
	}
}

static zend_op_array* php_dbc_create_contract(zend_op_array *active, zend_ast *attribute) {
	zend_op_array *contract = (zend_op_array*) 
		zend_arena_alloc(&CG(arena), sizeof(zend_op_array));
	zend_ast *ret;
	zend_oparray_context context = CG(context);

	init_op_array(contract, ZEND_USER_FUNCTION, 1);

	contract->T = active->T;
	contract->last_var = active->last_var;

	contract->vars = 
		(zend_string**) ecalloc(sizeof(zend_string*), active->last_var);
	memcpy(contract->vars, active->vars, sizeof(zend_string*) * active->last_var);

	contract->literals = (zval*) ecalloc(sizeof(zval), active->last_literal);
	memcpy(contract->literals, active->vars, sizeof(zval) * active->last_literal);

	contract->cache_size = active->cache_size;
	contract->run_time_cache = (void*) ecalloc(sizeof(void*), contract->cache_size);
	contract->scope = active->scope;

	php_dbc_recv_args(contract, active);

	CG(compiler_options) &= ~ ZEND_COMPILE_EXTENDED_INFO | ZEND_COMPILE_HANDLE_OP_ARRAY;
	CG(active_op_array) = contract;

	CG(context).opcodes_size = contract->last;
	CG(context).vars_size = contract->last_var;
	CG(context).literals_size = contract->last_literal;	

	ret = 
		zend_ast_create(ZEND_AST_RETURN, attribute);
	zend_compile_stmt(ret);
	/*zend_emit_final_return(0);*/
	pass_two(contract);
	
	CG(active_op_array) = active;
	CG(context) = context;
	CG(compiler_options) |= ZEND_COMPILE_EXTENDED_INFO | ZEND_COMPILE_HANDLE_OP_ARRAY;

	return contract;
}

static inline void php_dbc_compile(zend_op_array *ops) {
	zval *attribute;

	if (!ops->attributes) {
		return;
	}

	attribute = zend_hash_str_find(ops->attributes, ZEND_STRL("pre"));

	if (attribute && Z_TYPE_P(attribute) == IS_CONSTANT_AST){
		zend_op_array *contract = 
			php_dbc_create_contract(ops, Z_ASTVAL_P(attribute));
		
		if (contract) {
			zend_hash_index_update_ptr(
				&DBC(contracts), (zend_long) ops, contract);
		}
	}
}

static inline void php_dbc_fcall_enter(zend_op_array *unused) {
	zend_execute_data *frame = EG(current_execute_data);
	zend_execute_data *call = frame->call;

	if (!call || !call->func || 
		call->func->type != ZEND_USER_FUNCTION || 
		!call->func->op_array.attributes) {
		return;
	}

	{
		zend_op_array *contract = zend_hash_index_find_ptr(&DBC(contracts), (zend_long) call->func);
		zval closure;

		if (!contract) {
			return;
		}

		zend_create_closure(
			&closure, contract, 
			call->func->common.scope, call->func->common.scope, Z_OBJ(call->This));

		if (Z_TYPE(closure) == IS_OBJECT) {
			zend_fcall_info fci = empty_fcall_info;
			zend_fcall_info_cache fcc = empty_fcall_info_cache;
			zval rv;
			char *errstr = NULL;

			if (zend_fcall_info_init(&closure, 0, &fci, &fcc, NULL, &errstr) != SUCCESS) {
				zval_ptr_dtor(&closure);
				return;
			}

			php_var_dump(ZEND_CALL_ARG(call, 1));			

			if (zend_fcall_info_argp(&fci, ZEND_CALL_NUM_ARGS(call), ZEND_CALL_ARG(call, 1)) != SUCCESS) {
				zval_ptr_dtor(&closure);
				return;
			}

			fci.retval = &rv;

			if (zend_call_function(&fci, &fcc) != SUCCESS) {
				zval_ptr_dtor(&closure);
				return;
			}

			if (!zend_is_true(&rv)) {
				zval *ast = zend_hash_str_find(call->func->op_array.attributes, ZEND_STRL("pre"));

				zend_string *expr = 
					zend_ast_export("pre(", Z_ASTVAL_P(ast), ")");
				
				zend_throw_exception_ex(spl_ce_RuntimeException, 0, 
					"Pre condition failed %s", ZSTR_VAL(expr));
				
				zend_string_release(expr);
			}

			zend_fcall_info_args_clear(&fci, 1);
			zval_ptr_dtor(&rv);
		}

		zval_ptr_dtor(&closure);
	}
}

static inline void php_dbc_fcall_leave(zend_op_array *unused) {
	
}

/* {{{ PHP_INI
 */
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("dbc.enabled", "1", PHP_INI_SYSTEM, OnUpdateBool, enabled, zend_dbc_globals, dbc_globals)
PHP_INI_END()
/* }}} */

/* {{{ php_dbc_init_globals
 */
static void php_dbc_init_globals(zend_dbc_globals *dbc) {
	memset(dbc, 0, sizeof(zend_dbc_globals));
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(dbc)
{
	ZEND_INIT_MODULE_GLOBALS(dbc, php_dbc_init_globals, NULL);

	REGISTER_INI_ENTRIES();

	if (zend_get_extension("dbc")) {
		zend_error_noreturn(E_ERROR, 
			"dbc must be loaded as a normal PHP module");
		return FAILURE;
	}

	zend_register_extension(&zend_extension_entry, NULL);

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(dbc)
{
	UNREGISTER_INI_ENTRIES();

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(dbc)
{
#if defined(COMPILE_DL_DBC) && defined(ZTS)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif

	DBC(options) = CG(compiler_options);

	CG(compiler_options) |= 
		ZEND_COMPILE_EXTENDED_INFO | ZEND_COMPILE_HANDLE_OP_ARRAY;

	zend_hash_init(&DBC(contracts), 8, NULL, php_dbc_destroy_contract, 0);

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(dbc)
{
	CG(compiler_options) = DBC(options);

	zend_hash_destroy(&DBC(contracts));
	
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(dbc)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "dbc support", "enabled");
	php_info_print_table_end();
}
/* }}} */

/* {{{ */
zend_module_entry dbc_module_entry = {
	STANDARD_MODULE_HEADER,
	"dbc",
	NULL,
	PHP_MINIT(dbc),
	PHP_MSHUTDOWN(dbc),
	PHP_RINIT(dbc),	
	PHP_RSHUTDOWN(dbc),
	PHP_MINFO(dbc),
	PHP_DBC_VERSION,
	STANDARD_MODULE_PROPERTIES
};

#ifndef ZEND_EXT_API
#define ZEND_EXT_API    ZEND_DLEXPORT
#endif
ZEND_EXTENSION();

ZEND_EXT_API zend_extension zend_extension_entry = {
	PHP_DBC_EXTNAME,
	PHP_DBC_VERSION,
	"Joe Watkins <krakjoe@php.net>",
	"https://github.com/krakjoe/dbc",
	"Copyright (c) 2016",
	NULL,
	NULL,            /* shutdown_func_t */
	NULL,            /* activate_func_t */
	NULL,            /* deactivate_func_t */
	NULL,            /* message_handler_func_t */
	php_dbc_compile, /* op_array_handler_func_t */
	NULL, 			 /* statement_handler_func_t */
	php_dbc_fcall_enter, /* fcall_begin_handler_func_t */
	php_dbc_fcall_leave, /* fcall_end_handler_func_t */
	NULL,      		 /* op_array_ctor_func_t */
	NULL,      		 /* op_array_dtor_func_t */
	STANDARD_ZEND_EXTENSION_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_DBC
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(dbc)
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
