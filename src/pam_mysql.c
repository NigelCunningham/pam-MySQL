/*
 * PAM module for MySQL
 *
 * Copyright (C) 1998-2005 Gunay Arslan and the contributors.
 * Copyright (C) 2015-2017 Nigel Cunningham and contributors.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Original Version written by: Gunay ARSLAN <arslan@gunes.medyatext.com.tr>
 * This version by: James O'Kane <jo2y@midnightlinux.com>
 * Modifications by Steve Brown, <steve@electronic.co.uk>
 *      B.J. Black, <bj@taos.com>
 *      Kyle Smith, <kyle@13th-floor.org>
 * Patch integration by Moriyoshi Koizumi, <moriyoshi@at.wakwak.com>,
 * based on the patches by the following contributors:
 *        Paul Bryan (check_acct_mgmt service support)
 *        Kev Green (Documentation, UNIX socket option)
 *        Kees Cook (Misc. clean-ups and more)
 *        Fredrik Rambris (RPM spec file)
 *        Peter E. Stokke (chauthtok service support)
 *        Sergey Matveychuk (OpenPAM support)
 * Package unmaintained for some years; now taken care of by Nigel Cunningham
 *   https://github.com/NigelCunningham/pam-MySQL
 */

#define _GNU_SOURCE

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include "os_dep.h"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,
        int flags, int argc, const char **argv);
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
        const char **argv);
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
        const char **argv);
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
        const char **argv);
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
        const char **argv);
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
        const char **argv);

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_mysql_modstruct = {
    PAM_MODULE_NAME,
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    pam_sm_chauthtok
};

#endif
/* vim: set expandtab sw=4 ts=4 textwidth=80 : */
