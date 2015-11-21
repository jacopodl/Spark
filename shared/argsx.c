/*
	* <ArgsX, The simple C/C++ options parser.>
	* Copyright (C) <2014-2015> <Jacopo De Luca>
	*
	* This program is free software: you can redistribute it and/or modify
	* it under the terms of the GNU General Public License as published by
	* the Free Software Foundation, either version 3 of the License, or
	* (at your option) any later version.

	* This program is distributed in the hope that it will be useful,
	* but WITHOUT ANY WARRANTY; without even the implied warranty of
	* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
	* GNU General Public License for more details.

	* You should have received a copy of the GNU General Public License
	* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "argsx.h"

char *ax_curr; // Pointer to current position string
char *ax_arg; // Pointer to arg
int ax_cursor = 1; // Current position
int ax_opterr = 1; // Show errors
short ax_etype = -1; // Error type
unsigned short ax_loptidx; // Long options index


int argsx(int argc, char **argv, char *opt, ax_lopt *lopt, unsigned short lopt_size, char tr)
{
	static unsigned short cmpd_arg = 1;
	static unsigned short cmpd_opt = 0;

	ax_curr = argv[ax_cursor];
	if (ax_cursor >= argc)
		return -1;

	if (*ax_curr == tr)
	{
		if (*++ax_curr == tr&&lopt != NULL)
		{
			/* Long */
			ax_curr++;
			unsigned short i;
			for (i = 0; i < (lopt_size / sizeof(ax_lopt)); i++)
			{
				if (strcmp(lopt[i].name, ax_curr) == 0)
				{
					int ret = ((int)lopt[i].opt == 0) ? ARGSX_LOPT : ((int)lopt[i].opt);
					ax_loptidx = i;
					if (lopt[i].args == ARGSX_NOARG)
					{
						ax_cursor++;
						return ret;
					}
					else
					{
						ax_cursor++;
						if (ax_cursor >= argc || *argv[ax_cursor] == tr)
						{
							if (ax_opterr)
								fprintf(stderr, "Option --%s requires an argument\n", ax_curr);
							ax_etype = long_opt;
							return ARGSX_FEW_ARGS;
						}
						ax_arg = argv[ax_cursor++];
						return ret;
					}
				}
			}
			if (ax_opterr)
				fprintf(stderr, "Illegal option: --%s\n", ax_curr);
			ax_etype = long_opt;
			return ARGSX_BAD_OPT;
		}
		/* Short */
		ax_curr += cmpd_opt;
		char *subopt, ret = *ax_curr;
		if ((subopt = strchr(opt, *ax_curr)) != 0)
		{
			if (*++subopt == '!')
			{
				if (ax_cursor + cmpd_arg >= argc || *argv[ax_cursor + cmpd_arg] == tr)
				{
					if (strlen(ax_curr + 1) > 0 && cmpd_arg==1)
					{
						ax_arg = ax_curr+1;
						ax_cursor++;
						return ret;
					}
					if (ax_opterr)
						fprintf(stderr, "Option -%c requires an argument\n", *ax_curr);
					ax_etype = short_opt;
					return ARGSX_FEW_ARGS;
				}
				ax_arg = argv[ax_cursor + cmpd_arg++];
			}
			unsigned len = strlen(ax_curr);
			if (len > 1 && cmpd_opt < len)
				cmpd_opt++;
			else
			{
				ax_cursor += cmpd_arg;
				cmpd_arg = 1;
				cmpd_opt = 0;
			}
			return ret;
		}
		else
		{
			if (ax_opterr)
				fprintf(stderr, "Illegal option: -%c\n", *ax_curr);
			ax_etype = short_opt;
			return ARGSX_BAD_OPT;
		}
	}
	ax_arg = argv[ax_cursor++];
	return ARGSX_NONOPT;
}
