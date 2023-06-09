
/**
 * test.c: C-based test for https://lkml.org/lkml/2012/1/11/394
 * Author: Tyler Hicks <tyhicks@canonical.com>
 *
 * Copyright (C) 2012 Canonical, Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int main(void)
{
	unsigned char buf[] = { 103, 0, 0, 0, 0, 220 };
	ssize_t written;
	int miscdev;

       
	miscdev = open("/dev/tse", O_WRONLY);
	if (miscdev < 0)
		return 1;

	written = write(miscdev, buf, 1073741824);

	close(miscdev);

	/* The write should fail */
	return written < 0 ? 0 : 2;
}
