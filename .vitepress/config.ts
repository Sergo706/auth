import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'jwtAuth',
  description: 'Documentation for the jwtAuth module',
  srcDir: 'docs',  
  outDir: '.vitepress/dist',
  cleanUrls: true,
  lang: 'en-US',
  lastUpdated: true,
  rewrites: {
    'README.md': 'index.md',
    '@riavzon/botdetector/README.md': '@riavzon/botdetector/index.md'
  },


  themeConfig: {
    siteTitle: 'jwtAuth',

    nav: [
      { text: 'Home', link: '/' },
      { text: 'API', link: '/globals' },
      { text: 'Bot Detector', link: '/@riavzon/botdetector/' },
      {
        text: 'Guides',
        items: [
          { text: 'Configuration', link: '/_media/CONFIGURATION' },
          { text: 'Architecture', link: '/_media/ARCHITECTURE' },
          { text: 'Deployment', link: '/_media/DEPLOYMENT' },
          { text: 'Development', link: '/_media/DEVELOPMENT' }
        ]
      }
    ],

  sidebar: [
    {
      text: 'Guide',
      items: [
        { text: 'Introduction', link: '/README' },
        { text: 'Configuration', link: '/_media/CONFIGURATION' },
        { text: 'Architecture', link: '/_media/ARCHITECTURE' },
        { text: 'Deployment', link: '/_media/DEPLOYMENT' },
        { text: 'API Routes', link: '/_media/API' },
        { text: 'Service Vs library', link: '/_media/SERVICE' },
        { text: 'Development', link: '/_media/DEVELOPMENT' }
      ]
    },
  {
      text: 'Reference',
      items: [
        { text: 'API', link: '/globals' },
        { text: 'Bot Detection API', link: '/@riavzon/botdetector/globals' }
      ]
    }
  ],

    search: { provider: 'local' },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/riavzon/jwtauth' }
    ],

    editLink: {
      pattern: 'https://github.com/riavzon/jwtauth/edit/main/docs/:path',
      text: 'Edit this page on GitHub'
    },

    footer: {
      message: 'Released under the MIT License.',
      copyright: '© 2025–present Sergio Riavzon'
    }
  },


})
