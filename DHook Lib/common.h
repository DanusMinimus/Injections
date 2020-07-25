#pragma once

/*##############################Includes##########################################*/
#include <stdint.h>

/*##############################Typedef#########################################*/
typedef uint8_t bool_t;

/*##############################Macros#########################################*/
#define SAFE_FREE(_pointer)\
do { \
   if(NULL != _pointer)\
   {\
	   free(_pointer);\
	   _pointer = NULL;\
   }\
}while(0)\


#define SAFE_CLOSE(_file)\
do { \
   if(NULL != _file)\
   {\
	   fclose(_file);\
	   _file = NULL;\
   }\
}while(0)\


#define IS_SUCCESS(_result, _label, _ret, _value)\
do {\
		if (_value != _result)\
		{\
			_ret = _result; \
			goto _label; \
		}\
}while (0)\


#define IS_NULL(_func_name, _result, _label)\
if (NULL == _result)\
{\
	printf("%s failed! error code: %d\n", _func_name, GetLastError());\
	goto _label;\
}\


#define IS_ZERO(_func_name, _result, _label)\
if (0 == _result)\
{\
	printf("%s failed! error code: %d\n", _func_name, GetLastError()); \
	goto _label; \
}\

#define IS_NOT_ZERO(_result, _label, _ret, _value)\
do {\
		if (0 != _result)\
		{\
			_ret = _value; \
			goto _label; \
		}\
}while (0)\
