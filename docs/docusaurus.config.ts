import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'Citadel',
  tagline: 'Secure Android Virtual Machine',
  favicon: 'img/favicon.png',

  future: {
    v4: true,
  },

  url: 'https://rukmaldias.github.io',
  baseUrl: '/citadel/',

  organizationName: 'rukmaldias',
  projectName: 'citadel',

  onBrokenLinks: 'throw',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          routeBasePath: '/',
          sidebarPath: './sidebars.ts',
          editUrl: 'https://github.com/rukmaldias/citadel/tree/main/docs/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    image: 'img/docusaurus-social-card.jpg',
    colorMode: {
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: 'Citadel',
      logo: {
        alt: 'Citadel Logo',
        src: 'img/logo.png',
      },
      items: [
        {
          href: 'https://github.com/rukmaldias/citadel',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
  style: 'dark',
  copyright: `Copyright © ${new Date().getFullYear()} Citadel. Built with Docusaurus.`,
},
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
  } satisfies Preset.ThemeConfig,
};

export default config;