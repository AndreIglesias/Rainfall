/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   source.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ciglesia <ciglesia@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/06 18:51:32 by ciglesia          #+#    #+#             */
/*   Updated: 2024/02/23 17:39:46 by ciglesia         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>
#include <stdlib.h>

int n()
{
  char v4[520]; // [esp+10h] [ebp-208h] BYREF

  fgets(v4, 512, stdin);
  printf(v4);
  exit(1);
}

int o()
{
  system("/bin/sh");
  _exit(1);
}

int main() {
    return (n());
}
