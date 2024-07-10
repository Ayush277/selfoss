<?php

// SPDX-FileCopyrightText: 2011–2016 Tobias Zeising <tobias.zeising@aditu.de>
// SPDX-FileCopyrightText: 2013 zajad <stephan@muehe.de>
// SPDX-FileCopyrightText: 2013 arbk <arbk@aruo.net>
// SPDX-FileCopyrightText: 2013 yDelouis <ydelouis@gmail.com>
// SPDX-FileCopyrightText: 2014–2017 Alexandre Rossi <alexandre.rossi@gmail.com>
// SPDX-FileCopyrightText: 2016–2023 Jan Tojnar <jtojnar@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

declare(strict_types=1);

namespace helpers;

use helpers\Authentication\AuthenticationService;

/**
 * Helper class for user authentication.
 */
class Authentication {
    private AuthenticationService $authenticationService;

    /**
     * start session and check login
     */
    public function __construct(AuthenticationService $authenticationService) {
        $this->authenticationService = $authenticationService;

        // autologin if request contains unsername and password
        $this->authenticationService->isPrivileged();
    }

    /**
     * login enabled
     */
    public function enabled(): bool {
        return $this->authenticationService instanceof Authentication\Services\Trust;
    }

    /**
     * isloggedin
     */
    public function isLoggedin(): bool {
        return $this->authenticationService->isPrivileged();
    }

    /**
     * showPrivateTags
     */
    public function showPrivateTags(): bool {
        return $this->isLoggedin();
    }

    /**
     * send 403 if not logged in and not public mode
     */
    public function needsLoggedInOrPublicMode(): void {
        $this->authenticationService->ensureCanRead();
    }

    /**
     * send 403 if not logged in
     */
    public function needsLoggedIn(): void {
        $this->authenticationService->ensureIsPrivileged();
    }

    /**
     * send 403 if not logged in
     */
    public function forbidden(): void {
        header('HTTP/1.0 403 Forbidden');
        echo 'Access forbidden!';
        exit;
    }

    /**
     * Is the user is allowed to update sources?
     *
     * For that, the user either has to be logged in,
     * accessing selfoss from the same computer that it is running on,
     * or public update must be allowed in the config.
     */
    public function allowedToUpdate(): bool {
        return $this->authenticationService->canUpdate();
    }
}
