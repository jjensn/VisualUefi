/*
* Basic types definitions
*
* Copyright 1996 Alexandre Julliard
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2.1 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library; if not, write to the Free Software
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
*/

#ifndef _WINDEF_
#define _WINDEF_
#endif
#ifndef WINVER
#define WINVER 0x0500
#endif

#ifndef NO_STRICT
# ifndef STRICT
#  define STRICT
# endif /* STRICT */
#endif /* NO_STRICT */

#ifdef __cplusplus
extern "C" {
#endif

	/* Calling conventions definitions */

#if (defined(__x86_64__) || defined(__powerpc64__) || defined(__sparc64__) || defined(__aarch64__)) && !defined(_WIN64)
#define _WIN64
#endif

#ifndef _WIN64
# if defined(__i386__) && !defined(_X86_)
#  define _X86_
# endif
# if defined(_X86_) && !defined(__i386__)
#  define __i386__
# endif
#endif

#ifndef __stdcall
# ifdef __i386__
#  ifdef __GNUC__
#   if (__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 2)) || defined(__APPLE__)
#    define __stdcall __attribute__((__stdcall__)) __attribute__((__force_align_arg_pointer__))
#   else
#    define __stdcall __attribute__((__stdcall__))
#   endif
#  elif defined(_MSC_VER)
	/* Nothing needs to be done. __stdcall already exists */
#  else
#   error You need to define __stdcall for your compiler
#  endif
# elif defined(__x86_64__) && defined (__GNUC__)
#  define __stdcall __attribute__((ms_abi))
# else  /* __i386__ */
#  define __stdcall
# endif  /* __i386__ */
#endif /* __stdcall */

#ifndef __cdecl
# if defined(__i386__) && defined(__GNUC__)
#   if (__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 2)) || defined(__APPLE__)
#   define __cdecl __attribute__((__cdecl__)) __attribute__((__force_align_arg_pointer__))
#  else
#   define __cdecl __attribute__((__cdecl__))
#  endif
# elif defined(__x86_64__) && defined (__GNUC__)
#  define __cdecl __attribute__((ms_abi))
# elif !defined(_MSC_VER)
#  define __cdecl
# endif
#endif /* __cdecl */

#ifndef __ms_va_list
# if defined(__x86_64__) && defined (__GNUC__)
#  define __ms_va_list __builtin_ms_va_list
#  define __ms_va_start(list,arg) __builtin_ms_va_start(list,arg)
#  define __ms_va_end(list) __builtin_ms_va_end(list)
# else
#  define __ms_va_list va_list
#  define __ms_va_start(list,arg) va_start(list,arg)
#  define __ms_va_end(list) va_end(list)
# endif
#endif

#ifdef __WINESRC__
#define __ONLY_IN_WINELIB(x)	do_not_use_this_in_wine
#else
#define __ONLY_IN_WINELIB(x)	x
#endif

#ifndef pascal
#define pascal      __ONLY_IN_WINELIB(__stdcall)
#endif
#ifndef _pascal
#define _pascal	    __ONLY_IN_WINELIB(__stdcall)
#endif
#ifndef _stdcall
#define _stdcall    __ONLY_IN_WINELIB(__stdcall)
#endif
#ifndef _fastcall
#define _fastcall   __ONLY_IN_WINELIB(__stdcall)
#endif
#ifndef __fastcall
#define __fastcall  __ONLY_IN_WINELIB(__stdcall)
#endif
#ifndef __export
#define __export    __ONLY_IN_WINELIB(__stdcall)
#endif
#ifndef cdecl
#define cdecl       __ONLY_IN_WINELIB(__cdecl)
#endif
#ifndef _cdecl
#define _cdecl      __ONLY_IN_WINELIB(__cdecl)
#endif

#ifndef near
#define near        __ONLY_IN_WINELIB(/* nothing */)
#endif
#ifndef far
#define far         __ONLY_IN_WINELIB(/* nothing */)
#endif
#ifndef _near
#define _near       __ONLY_IN_WINELIB(/* nothing */)
#endif
#ifndef _far
#define _far        __ONLY_IN_WINELIB(/* nothing */)
#endif
#ifndef NEAR
#define NEAR        __ONLY_IN_WINELIB(/* nothing */)
#endif
#ifndef FAR
#define FAR         __ONLY_IN_WINELIB(/* nothing */)
#endif

#ifndef _MSC_VER
# ifndef _declspec
#  define _declspec(x)    __ONLY_IN_WINELIB(/* nothing */)
# endif
# ifndef __declspec
#  define __declspec(x)   __ONLY_IN_WINELIB(/* nothing */)
# endif
#endif

#ifdef _MSC_VER
# define inline __inline
#endif

#define CALLBACK    __stdcall
#define WINAPI      __stdcall
#define APIPRIVATE  __stdcall
#define PASCAL      __stdcall
#define CDECL       __cdecl
#define _CDECL      __cdecl
#define WINAPIV     __cdecl
#define APIENTRY    WINAPI
#define CONST       const

	/* Misc. constants. */

#undef NULL
#ifdef __cplusplus
#define NULL  0
#else
#define NULL  ((void*)0)
#endif

#ifdef FALSE
#undef FALSE
#endif
#define FALSE 0

#ifdef TRUE
#undef TRUE
#endif
#define TRUE  1

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef OPTIONAL
#define OPTIONAL
#endif

	/* Standard data types */

	typedef void                                   *LPVOID;
	typedef const void                             *LPCVOID;
	typedef int             BOOL, *PBOOL, *LPBOOL;
	typedef unsigned char   BYTE, *PBYTE, *LPBYTE;
	typedef unsigned char   UCHAR, *PUCHAR;
	typedef unsigned short  WORD, *PWORD, *LPWORD;
	typedef unsigned short  USHORT, *PUSHORT;
	typedef int             INT, *PINT, *LPINT;
	typedef unsigned int    UINT, *PUINT;
	typedef float           FLOAT, *PFLOAT;
	typedef char                        *PSZ, *PCHAR;
	typedef void *PVOID;
	typedef long                                  LONG, *LPLONG;
	typedef unsigned long   DWORD, *PDWORD, *LPDWORD;
	typedef unsigned long   ULONG, *PULONG, *ULONG_PTR;
	typedef unsigned long long ULONGLONG;
	typedef long long LONGLONG;
	typedef long NTSTATUS;
	typedef char CHAR;
	typedef unsigned short WCHAR;
	typedef WCHAR *PWCHAR, *PWSTR;

#define CONTAINING_RECORD(address, type, field) \
                ((type *)((char *)(address) - (char *)(&((type *)0)->field)))