/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   source.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ciglesia <ciglesia@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/06 18:51:32 by ciglesia          #+#    #+#             */
/*   Updated: 2024/02/23 09:53:40 by ciglesia         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>
#include <stdlib.h>

int m = 0;

int p(int buffer) {
    return (printf(buffer));
}

int n()
{
  int eax;      // EAX
  char v1[520]; // [esp+10h] [ebp-208h] BYREF

  fgets(v1, 512, stdin);
  p(v1);
  eax = m;
  if ( m == 16930116 )
    return system("/bin/cat /home/user/level5/.pass");
  return eax;
}
int main() {
    int eax;

    n();
    return (eax);
}
