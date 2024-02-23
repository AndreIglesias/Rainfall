/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   source.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ciglesia <ciglesia@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/06 18:51:32 by ciglesia          #+#    #+#             */
/*   Updated: 2024/02/23 17:00:22 by Clkuznie         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, const char **argv, const char **envp)
{
    if (atoi(argv[1]) != 423)
    {
        // Write "No !" to stderr
        fwrite("No !\n", sizeof(char), 5, stderr);
    } 
    else 
    {
        // Execute /bin/sh
        char *shell_cmd = strdup("/bin/sh");
        setresgid(getegid(), getegid(), getegid());
        setresuid(geteuid(), geteuid(), geteuid());
        execv(shell_cmd, argv);
    }
    return (0);
}
