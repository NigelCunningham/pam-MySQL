#include "alloc.h"

/**
 * Allocate space for an array of elements of equal size.
 *
 * The product of the size and number of items must not exceed the capacity
 * of a signed int (if I've understood the check correctly!)
 *
 * Memory is cleared.
 *
 * @param size_t nmemb
 *   The number of array elements.
 * @param size_t size
 *   The size of each element.
 *
 * @return mixed
 *   NULL if no allocation is made, or a cleared array of the requested size.
 */
void *xcalloc(size_t nmemb, size_t size)
{
  void *retval;
  double v = ((double)size) * (int)(nmemb & (((size_t)-1) >> 1));

  if (v != nmemb * size) {
    return NULL;
  }

  retval = calloc(nmemb, size);

  return retval;
}

/**
 * Adjust the amount of space allocated for an array of elements of equal size.
 *
 * The product of the size and number of items must not exceed the capacity
 * of a signed int.
 *
 * @param size_t nmemb
 *   The number of array elements.
 * @param size_t size
 *   The size of each element.
 *
 * @return mixed
 *   NULL if no allocation is made, or a cleared array of the requested size.
 */
void *xrealloc(void *ptr, size_t nmemb, size_t size)
{
  void *retval;
  size_t total = nmemb * size;

  if (((double)size) * (int)(nmemb & (((size_t)-1) >> 1)) != total) {
    return NULL;
  }

  retval = realloc(ptr, total);

  return retval;
}

/**
 * Duplicate a string.
 *
 * @param const char *ptr
 *   The string to be duplicated.
 *
 * @return mixed.
 *   A copy of the string or NULL if memory allocation failed.
 */
char *xstrdup(const char *ptr)
{
  size_t len = strlen(ptr) + sizeof(char);
  char *retval = xcalloc(sizeof(char), len);

  if (retval == NULL) {
    return NULL;
  }

  memcpy(retval, ptr, len);

  return retval;
}

/**
 * Free memory allocated with malloc.
 *
 * @param void *ptr
 *   A pointer to the allocation.
 */
void xfree(void *ptr)
{
  if (ptr != NULL) {
    free(ptr);
  }
}

/**
 * Clear memory and free it.
 *
 * @param char *ptr
 *   The memory to be cleared and freed.
 */
void xfree_overwrite(char *ptr)
{
  if (ptr != NULL) {
    char *p;
    for (p = ptr; *p != '\0'; p++) {
      *p = '\0';
    }
    free(ptr);
  }
}

