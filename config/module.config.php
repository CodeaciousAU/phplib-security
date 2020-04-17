<?php

use Codeacious\Security\Authentication\Adapter as AuthenticationAdapter;
use Codeacious\Security\Authentication\AuthenticationListener;
use Codeacious\Security\Authentication\AuthenticationListenerFactory;
use Codeacious\Security\Authentication\DummyUserLookupStrategy;
use Codeacious\Security\Authentication\JwtUserLookupStrategy;
use Codeacious\Security\Authorization\Adapter as AuthorizationAdapter;
use Codeacious\Security\Authorization\AuthorizationListener;
use Codeacious\Security\Authorization\AuthorizationListenerFactory;
use Codeacious\Security\Controller\Plugin as ControllerPlugin;
use Codeacious\Security\Doctrine\AuditEventSubscriber;
use Codeacious\Security\Doctrine\AuditEventSubscriberFactory;
use Codeacious\Security\SecurityService;
use Codeacious\Security\SecurityServiceFactory;
use Codeacious\Security\Session\CookieService;
use Codeacious\Security\Session\CookieServiceFactory;
use Codeacious\Security\Session\TokenProvider;
use Codeacious\Security\View\Helper as ViewHelper;
use Codeacious\Security\WebTokenManager;
use Codeacious\Security\WebTokenManagerFactory;
use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\InvokableFactory;

return [
    'security' => [
        'session' => [
            'cookie' => [
                'name' => 'Identity',
                'is_secure' => false,
                'http_only' => true,
                'validity_period' => 0, //zero means the duration of the browser session
            ],
            'token_provider' => TokenProvider\JwtProvider::class,
        ],
        'web_token_manager' => [
            'public_key' => '',
            'private_key' => '',
            'algorithm' => 'RS256',
            'issuer' => '',
            'lifetime' => 86400,
        ],
    ],

    'authentication' => [
        'adapters' => [
            'factories' => [
                AuthenticationAdapter\CookieAdapter::class => AuthenticationAdapter\CookieAdapterFactory::class,
                AuthenticationAdapter\JwtBearerAdapter::class => AuthenticationAdapter\JwtBearerAdapterFactory::class,
            ],
        ],
        'rules' => [],
        'user_lookup_strategy' => JwtUserLookupStrategy::class,
    ],

    'authorization' => [
        'adapters' => [
            'factories' => [
                AuthorizationAdapter\ControllerAclAdapter::class => InvokableFactory::class,
            ],
        ],
        'rules' => [],
    ],

    'service_manager' => [
        'factories' => [
            AuditEventSubscriber::class => AuditEventSubscriberFactory::class,
            AuthenticationListener::class => AuthenticationListenerFactory::class,
            AuthorizationListener::class => AuthorizationListenerFactory::class,
            CookieService::class => CookieServiceFactory::class,
            DummyUserLookupStrategy::class => InvokableFactory::class,
            JwtUserLookupStrategy::class => InvokableFactory::class,
            SecurityService::class => SecurityServiceFactory::class,
            TokenProvider\JwtProvider::class => TokenProvider\JwtProviderFactory::class,
            WebTokenManager::class => WebTokenManagerFactory::class,
        ],
    ],

    'controller_plugins' => [
        'aliases' => [
            'authAssertion' => ControllerPlugin\AuthAssertion::class,
            'authResult' => ControllerPlugin\AuthResult::class,
            'currentAuditUser' => ControllerPlugin\CurrentAuditUser::class,
            'currentPrincipal' => ControllerPlugin\CurrentPrincipal::class,
            'currentUser' => ControllerPlugin\CurrentUser::class,
            'isLoggedIn' => ControllerPlugin\IsLoggedIn::class,
        ],
        'factories' => [
            ControllerPlugin\AuthAssertion::class => InvokableFactory::class,
            ControllerPlugin\AuthResult::class => InvokableFactory::class,
            ControllerPlugin\CurrentAuditUser::class => function(ContainerInterface $container) {
                /* @var $securityService SecurityService */
                $securityService = $container->get(SecurityService::class);
                return new ControllerPlugin\CurrentAuditUser($securityService);
            },
            ControllerPlugin\CurrentPrincipal::class => function(ContainerInterface $container) {
                /* @var $securityService SecurityService */
                $securityService = $container->get(SecurityService::class);
                return new ControllerPlugin\CurrentPrincipal($securityService);
            },
            ControllerPlugin\CurrentUser::class => function(ContainerInterface $container) {
                /* @var $securityService SecurityService */
                $securityService = $container->get(SecurityService::class);
                return new ControllerPlugin\CurrentUser($securityService);
            },
            ControllerPlugin\IsLoggedIn::class => function(ContainerInterface $container) {
                /* @var $securityService SecurityService */
                $securityService = $container->get(SecurityService::class);
                return new ControllerPlugin\IsLoggedIn($securityService);
            },
        ],
    ],

    'view_helpers' => [
        'aliases' => [
            'currentUser' => ViewHelper\CurrentUser::class,
            'isImpersonationActive' => ViewHelper\IsImpersonationActive::class,
            'isLoggedIn' => ViewHelper\IsLoggedIn::class,
        ],
        'factories' => [
            ViewHelper\CurrentUser::class => function(ContainerInterface $container) {
                /* @var $securityService SecurityService */
                $securityService = $container->get(SecurityService::class);
                return new ViewHelper\CurrentUser($securityService);
            },
            ViewHelper\IsImpersonationActive::class => function(ContainerInterface $container) {
                /* @var $securityService SecurityService */
                $securityService = $container->get(SecurityService::class);
                return new ViewHelper\IsImpersonationActive($securityService);
            },
            ViewHelper\IsLoggedIn::class => function(ContainerInterface $container) {
                /* @var $securityService SecurityService */
                $securityService = $container->get(SecurityService::class);
                return new ViewHelper\IsLoggedIn($securityService);
            },
        ],
    ],
];