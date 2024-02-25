/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   source.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ciglesia <ciglesia@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/06 18:51:32 by ciglesia          #+#    #+#             */
/*   Updated: 2024/02/24 17:11:10 by ciglesia         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>
#include <stdlib.h>

char *c = NULL;

int m()
{
  int eax;

  eax = time(0);
  return printf("%s - %d\n", c, eax);
}

int main(int argc, const char **argv, const char **envp)
{
  int eax; // eax
  _DWORD *v5; // [esp+18h] [ebp-8h]    argv[2]
  _DWORD *v6; // [esp+1Ch] [ebp-4h]    argv[1]

  v6 = (_DWORD *)malloc(8);
  *v6 = 1;
  v6[1] = malloc(8);
  v5 = (_DWORD *)malloc(8);
  *v5 = 2;
  v5[1] = malloc(8);
  strcpy(v6[1], argv[1]); // Vulnerable for buffer overflow
  strcpy(v5[1], argv[2]); // Vulnerable for buffer overflow
  eax = fopen("/home/user/level8/.pass", "r");
  fgets(&c, 68, eax); // 68 is the lenght of the flag from .pass
  // c has now the flag
  puts("~~"); // Call m() instead of puts()
  return 0;
}
