import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

// Oracle-inspired light Prism theme
const oraclePrismLight = {
  plain: {color: '#1B2A4A', backgroundColor: '#F5F6FA'},
  styles: [
    {types: ['comment', 'prolog', 'cdata'], style: {color: '#5A6472', fontStyle: 'italic' as const}},
    {types: ['punctuation'], style: {color: '#4A5568'}},
    {types: ['number', 'boolean', 'constant', 'symbol'], style: {color: '#B85C00'}},
    {types: ['string', 'char', 'inserted'], style: {color: '#1A7A40'}},
    {types: ['operator', 'url', 'variable'], style: {color: '#0057B8'}},
    {types: ['keyword', 'atrule', 'deleted'], style: {color: '#C74634'}},
    {types: ['function', 'class-name'], style: {color: '#0057B8'}},
    {types: ['tag'], style: {color: '#C74634'}},
    {types: ['attr-name', 'selector'], style: {color: '#B85C00'}},
    {types: ['attr-value'], style: {color: '#1A7A40'}},
    {types: ['property'], style: {color: '#1B2A4A'}},
    {types: ['important', 'bold'], style: {fontWeight: 'bold' as const}},
    {types: ['italic'], style: {fontStyle: 'italic' as const}},
  ],
};

// Oracle-inspired dark Prism theme
const oraclePrismDark = {
  plain: {color: '#E5EAF0', backgroundColor: '#0F1E33'},
  styles: [
    {types: ['comment', 'prolog', 'cdata'], style: {color: '#7B8FA8', fontStyle: 'italic' as const}},
    {types: ['punctuation'], style: {color: '#A0B0C0'}},
    {types: ['number', 'boolean', 'constant', 'symbol'], style: {color: '#F0A070'}},
    {types: ['string', 'char', 'inserted'], style: {color: '#6BD98A'}},
    {types: ['operator', 'url', 'variable'], style: {color: '#5AADDF'}},
    {types: ['keyword', 'atrule', 'deleted'], style: {color: '#F07A6A'}},
    {types: ['function', 'class-name'], style: {color: '#5AADDF'}},
    {types: ['tag'], style: {color: '#F07A6A'}},
    {types: ['attr-name', 'selector'], style: {color: '#F0A070'}},
    {types: ['attr-value'], style: {color: '#6BD98A'}},
    {types: ['property'], style: {color: '#E5EAF0'}},
    {types: ['important', 'bold'], style: {fontWeight: 'bold' as const}},
    {types: ['italic'], style: {fontStyle: 'italic' as const}},
  ],
};

const config: Config = {
  title: 'Citadel',
  tagline: 'Cryptographically hardened virtual machine for Android',
  favicon: 'img/favicon.svg',

  future: {
    v4: true,
  },

  url: 'https://rukmaldias.github.io',
  baseUrl: '/citadel/',
  trailingSlash: false,

  organizationName: 'rukmaldias',
  projectName: 'citadel',

  onBrokenLinks: 'throw',
  markdown: {
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          editUrl: 'https://github.com/rukmaldias/citadel/edit/main/docs/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    colorMode: {
      defaultMode: 'light',
      disableSwitch: false,
      respectPrefersColorScheme: true,
    },
    image: 'img/logo.svg',
    navbar: {
      title: 'Citadel',
      logo: {
        alt: 'Citadel — secure Android VM',
        src: 'img/logo.svg',
      },
      style: 'dark',
      items: [
        {
          to: '/',
          label: 'Home',
          position: 'left',
          activeBaseRegex: '^/citadel/$',
        },
        {
          type: 'docSidebar',
          sidebarId: 'docs',
          position: 'left',
          label: 'Docs',
        },
        {
          href: 'https://github.com/rukmaldias/citadel',
          position: 'right',
          className: 'header-github-link',
          'aria-label': 'GitHub repository',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Documentation',
          items: [
            {label: 'Introduction', to: '/docs/intro'},
            {label: 'Requirements', to: '/docs/requirements'},
            {label: 'Architecture', to: '/docs/architecture'},
          ],
        },
        {
          title: 'Security',
          items: [
            {label: 'Cryptography', to: '/docs/cryptography'},
            {label: 'Security Design', to: '/docs/security-design'},
            {label: 'VM Design', to: '/docs/vm-design'},
          ],
        },
        {
          title: 'Integration',
          items: [
            {label: 'Kotlin Integration', to: '/docs/kotlin-integration'},
            {label: 'Asset Generation', to: '/docs/asset-generation'},
            {label: 'CI Practices', to: '/docs/ci-practices'},
            {label: 'GitHub', href: 'https://github.com/rukmaldias/citadel'},
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Citadel. Built with Docusaurus.`,
    },
    prism: {
      theme: oraclePrismLight,
      darkTheme: oraclePrismDark,
      additionalLanguages: ['rust', 'kotlin', 'bash', 'toml', 'groovy', 'java'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
