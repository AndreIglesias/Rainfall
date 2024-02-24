/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   source.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ciglesia <ciglesia@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/06 18:51:32 by ciglesia          #+#    #+#             */
/*   Updated: 2024/02/23 22:58:32 by ciglesia         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>
#include <stdlib.h>

int n()
{
  return (system("/bin/cat /home/user/level7/.pass"));
}

int m()
{
  return (puts("Nope"));
}

int main(int argc, const char **argv, const char **envp)
{
  int (**v4)(void); // [esp+18h] [ebp-8h]
  int v5; // [esp+1Ch] [ebp-4h]

  v5 = malloc(64);
  v4 = (int (**)(void))malloc(4);
  *v4 = m;
  strcpy(v5, argv[1]);
  return ((*v4)());
}
