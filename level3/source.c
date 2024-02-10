/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   source.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ciglesia <ciglesia@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/06 18:51:32 by ciglesia          #+#    #+#             */
/*   Updated: 2024/02/10 17:13:43 by ciglesia         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>

int m = 0;

int v() {
    int result;         // EAX
    char buffer[520];   // [esp+10h] [ebp-208h] BYREF
    fgets(buffer, 512, stdin);  // Read up to 512 characters from stdin
    printf(buffer); // Print the buffer
    result = m;
    if (m == 64) {  // @
        fwrite("Wait what?!\n", 1, 12, stdout);
        return (system("/bin/sh"));
    }
    return (result);
}

int main() {
    return (v());
}