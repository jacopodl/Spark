/*
 * Copyright (c) 2016 - 2017 Jacopo De Luca
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
*/

/**
 * @file spkerr.h
 * @brief Contains common error codes.
 */

#ifndef SPARK_SPKERR_H
#define SPARK_SPKERR_H

#define SPKERR_SUCCESS      0
#define SPKERR_ERROR        -1
#define SPKERR_ENINIT       -2
#define SPKERR_ENOSUPPORT   -3
#define SPKERR_ENOMEM       -4
#define SPKERR_EPERM        -5
#define SPKERR_ENODEV       -6
#define SPKERR_EINTR        -7
#define SPKERR_ESIZE        -8

/**
 * @brief Returns error message.
 * @param error Error number.
 * @return On success, pointer to the error message will returned, otherwise returns NULL.
 */
char *spark_strerror(int error);

#endif //SPARK_SPKERR_H
