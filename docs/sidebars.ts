import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docs: [
    {type: 'doc', id: 'intro', label: 'Introduction'},
    {
      type: 'category',
      label: 'Foundations',
      collapsed: false,
      items: [
        {type: 'doc', id: 'cryptography', label: 'Cryptography'},
        {type: 'doc', id: 'android-security', label: 'Android Security'},
        {type: 'doc', id: 'requirements', label: 'Requirements'},
      ],
    },
    {
      type: 'category',
      label: 'Architecture',
      collapsed: false,
      items: [
        {type: 'doc', id: 'architecture', label: 'System Architecture'},
        {type: 'doc', id: 'security-design', label: 'Security Design'},
        {type: 'doc', id: 'vm-design', label: 'VM Design'},
      ],
    },
    {
      type: 'category',
      label: 'Implementation',
      collapsed: false,
      items: [
        {type: 'doc', id: 'implementation', label: 'Implementation'},
        {type: 'doc', id: 'asset-generation', label: 'Asset Generation'},
        {type: 'doc', id: 'kotlin-integration', label: 'Kotlin Integration'},
      ],
    },
    {
      type: 'category',
      label: 'Operations',
      collapsed: false,
      items: [
        {type: 'doc', id: 'ci-practices', label: 'CI & Security Practices'},
        {type: 'doc', id: 'release-checklist', label: 'Release Checklist'},
      ],
    },
    {type: 'doc', id: 'glossary', label: 'Glossary'},
  ],
};

export default sidebars;
