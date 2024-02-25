/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   source.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ciglesia <ciglesia@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/06 18:51:32 by ciglesia          #+#    #+#             */
/*   Updated: 2024/02/25 01:55:55 by ciglesia         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *auth = NULL;
char *service = NULL;

int main(int argc, const char **argv, const char **envp)
{
  char *input;

  while ( 1 )
  {
    printf("%p, %p \n", auth, service);
    if ( !fgets(input, 128, stdin) )
      break;
    if ( !memcmp(input, "auth ", 5u) )
    {
      auth = malloc(4);
      *auth = 0;
      if ( strlen(input + 5) <= 30 )
        strcpy(auth, input + 5);
    }
    if ( !memcmp(input, "reset", 5u) )
      free(auth);
    if ( !memcmp(input, "service", 6u) )
      service = strdup(input + 7);
    if ( !memcmp(input, "login", 5u) )
    {
      if ( auth[32] )
        system("/bin/sh");
      else
        fwrite("Password:\n", 1, 10, stdout);
    }
  }
  return 0;
}
