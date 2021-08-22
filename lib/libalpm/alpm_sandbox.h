/*
 *  sandbox.h
 *
 *  Copyright (c) 2021 Pacman Development Team <pacman-dev@archlinux.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef ALPM_SANDBOX_H
#define ALPM_SANDBOX_H

#ifdef __cplusplus
extern "C" {
#endif

int alpm_sandbox_child(const char *sandboxuser);

#ifdef __cplusplus
}
#endif
#endif /* ALPM_SANDBOX_H */
