// TypeDoc configuration. This is JavaScript rather than JSON because
// `markdownItLoader` (below) is a function, and a function cannot be expressed
// in typedoc.json.
/** @type {Partial<import('typedoc').TypeDocOptions>} */
export default {
  entryPoints: [
    'src/index.ts',
    'src/browser/index.ts',
    'src/middleware/index.ts',
    'src/nestjs/index.ts',
  ],
  out: '_docs',
  name: 'AXIAM TypeScript SDK',
  // The site is published per release tag, so the header must say WHICH
  // release it documents: this appends " - v<package.json version>" to the
  // title, and docs-publish.yml gates that the version equals the tag.
  includeVersion: true,
  excludeInternal: true,

  // markdown-it linkifies *schemeless* text that merely looks like a domain,
  // and `.md` is a real TLD (Moldova) — so every prose reference of the form
  // "CONTRACT.md §8", in this README and in doc comments alike, rendered as a
  // link to http://CONTRACT.md: 143 dead links across the site, one of them 41
  // times on the home page alone. Turning `fuzzyLink` off is the narrowest cut
  // that removes them: URLs that carry a scheme (https://v8.dev/…) still
  // autolink, as do ordinary [text](target) links and <https://…> autolinks.
  markdownItLoader(parser) {
    parser.linkify.set({ fuzzyLink: false });
  },

  highlightLanguages: ['typescript', 'javascript', 'json', 'tsx', 'jsx', 'bash', 'console', 'http', 'text'],
  externalSymbolLinkMappings: {
    '@types/node': {
      '"node:http".Server': 'https://nodejs.org/api/http.html#class-httpserver',
      '"node:http".request': 'https://nodejs.org/api/http.html#httprequestoptions-callback',
      '"node:http".createServer': 'https://nodejs.org/api/http.html#httpcreateserveroptions-requestlistener',
      '"node:http".ClientRequest': 'https://nodejs.org/api/http.html#class-httpclientrequest',
    },
  },
  validation: {
    notDocumented: true,
  },
  treatValidationWarningsAsErrors: true,
};
