/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   source.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ciglesia <ciglesia@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/06 18:51:32 by ciglesia          #+#    #+#             */
/*   Updated: 2024/02/10 10:06:58 by ciglesia         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// ebp + 4 = return address , EIP next instruction to execute
int p()
{
  char buffer[64]; // ebp+0x4C - ebp+0xC
  int arg;
  int eax;
  int edx;

  fflush(stdout);   // Flush stdout buffer
  gets(buffer);     // Again, possible buffer overflow
  memcpy(eax, &buffer[80], 4);  // Copy EIP (return address) from buffer[80] to eax
  arg = &buffer[64];  // Set arg to point to the end of buffer
  memcpy(arg, eax, 4);  // Copy 4 bytes from eax to arg
  memcpy(eax, arg, 4);  // Copy 4 bytes from arg to eax
  
  if ( (eax & 0xB0000000) == 0xB0000000 )
  {
    printf("(%p)\n", arg);
    exit(1);
  }
  puts(buffer);
  return (strdup(buffer));
}

int main(int argc, const char **argv, const char **envp)
{
  return (p());
}