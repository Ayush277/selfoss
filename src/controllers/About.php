<?php

declare(strict_types=1);

namespace controllers;

use helpers\Authentication;
use helpers\Authentication\AuthenticationService;
use helpers\Configuration;
use helpers\View;

/**
 * Controller for instance information API
 */
class About {
    private bool $authenticationEnabled;
    private Configuration $configuration;
    private View $view;

    public function __construct(AuthenticationService $authenticationService, Configuration $configuration, View $view) {
        $this->authenticationEnabled = !$authenticationService instanceof Authentication\Services\Trust;
        $this->configuration = $configuration;
        $this->view = $view;
    }

    /**
     * Provide information about the selfoss instance.
     * json
     */
    public function about(): void {
        $wallabag = !empty($this->configuration->wallabag) ? [
            'url' => $this->configuration->wallabag, // string
            'version' => $this->configuration->wallabagVersion, // int
        ] : null;

        $configuration = [
            'version' => SELFOSS_VERSION,
            'apiversion' => SELFOSS_API_VERSION,
            'configuration' => [
                'homepage' => $this->configuration->homepage ?: 'newest', // string
                'share' => $this->configuration->share, // string
                'wallabag' => $wallabag, // ?array
                'wordpress' => $this->configuration->wordpress, // ?string
                'mastodon' => $this->configuration->mastodon, // ?string
                'autoMarkAsRead' => $this->configuration->autoMarkAsRead, // bool
                'autoCollapse' => $this->configuration->autoCollapse, // bool
                'autoStreamMore' => $this->configuration->autoStreamMore, // bool
                'openInBackgroundTab' => $this->configuration->openInBackgroundTab, // bool
                'loadImagesOnMobile' => $this->configuration->loadImagesOnMobile, // bool
                'itemsPerPage' => $this->configuration->itemsPerpage, // int
                'unreadOrder' => $this->configuration->unreadOrder, // string
                'autoHideReadOnMobile' => $this->configuration->autoHideReadOnMobile, // bool
                'scrollToArticleHeader' => $this->configuration->scrollToArticleHeader, // bool
                'showThumbnails' => $this->configuration->showThumbnails, // bool
                'htmlTitle' => trim($this->configuration->htmlTitle), // string
                'allowPublicUpdate' => $this->configuration->allowPublicUpdateAccess, // bool
                'publicMode' => $this->configuration->public, // bool
                'authEnabled' => $this->authenticationEnabled, // bool
                'readingSpeed' => $this->configuration->readingSpeedWpm > 0 ? $this->configuration->readingSpeedWpm : null, // ?int
                'language' => $this->configuration->language === '0' ? null : $this->configuration->language, // ?string
                'userCss' => file_exists(BASEDIR . '/user.css') ? filemtime(BASEDIR . '/user.css') : null, // ?int
                'userJs' => file_exists(BASEDIR . '/user.js') ? filemtime(BASEDIR . '/user.js') : null, // ?int
            ],
        ];

        $this->view->jsonSuccess($configuration);
    }
}
