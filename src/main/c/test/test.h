/*
 * (C) Copyright ${year} Machine-to-Machine Intelligence (M2Mi) Corporation, all rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Contributors:
 *     Julien Niset
 */

#ifndef _test_h_
#define _test_h_

#include <stdio.h>

#include "../json/json.h"
#include "../crypto/crypto.h"
#include "../https/HTTPSClient.h"
#include "../auth/m2mi.h"

#define fail()	return __LINE__
#define done()  return 0;

static int test_passed = 0;
static int test_failed = 0;

static void test(int (*func)(void), const char *name) {
  printf("Running Test [%s]:\n", name);
	int r = func();
	if (r == 0) {
		test_passed++;
    printf("---> test result: SUCCESS.\n");
	} else {
		test_failed++;
		printf("---> test result: FAILED at line %d.\n", r);
	}
}

void run_test(void);

#endif
