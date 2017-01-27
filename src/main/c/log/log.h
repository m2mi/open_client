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

#ifndef _log_h_
#define _log_h_

#ifndef NDEBUG
#define debug(D, ...)
#else
#define debug(D, ...) fprintf(stderr, "DEBUG %s in '%s' line %d:  " D "\n", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif

#define error(D, ...) fprintf(stderr, "ERROR %s in '%s' line %d:  " D "\n", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#endif