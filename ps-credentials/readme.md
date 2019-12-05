# Pointcheval-Sanders Credential Scheme

Typescript implementation of the Pointcheval-Sanders credential scheme.

D. Pointcheval, O. Sanders, "Short Randomizable Signatures", 2016 - https://eprint.iacr.org/2015/525.pdf

## Installation

Clone the repository and run
```
npm install
```
in the ***ps-credentials*** directory.

## Using the library

If running your app in Node.js, simply do
```javascript
const pscreds = require("ps-credentials");
```

If you want to use the library in a browser script, make sure all contents of the *browser* folder are available and include them in your page:
```HTML
<script src="mcl_c.js"></script>
<script src="mcl.js"></script>
<script src="pscreds.js"></script>
```
then the library should be available for your page's scripts throught the global variable `pscreds`.

## Continue development

If you want to continue development on this project, you should follow the steps below.

### Gulp

Globally install Gulp
```
npm install -g gulp-cli
```

### and Prettier
to automatically format code
```
npm install -g prettier
```
Then add JsPrettier to your editor (https://prettier.io/).

### devdependencies
Install all dev dependencies from package.json

```
npm install --dev
```

---
## Usage

Use `gulp node` to compile TypeScript from ***src*** into ***dist*** directory.

Use `gulp browser` to create the files needed for enabling browser support. The files are then available in the ***browser*** folder.

Run `gulp` to do both of the above.

Use `gulp lint` to run tslint.

Use `gulp doc` to run typedoc and generate documentation.

### Testing

Use `npm test` to run all tests. Use `npm test -- --grep "test-name"` to run only tests that match the pattern.

Test files should end in `.spec.ts` and be placed in the ***src/tests*** directory.

---
## Useful links

- TypeScript and Gulp:
     - https://www.typescriptlang.org/docs/handbook/gulp.html
- Mocha + Chai:
     - https://journal.artfuldev.com/unit-testing-node-applications-with-typescript-using-mocha-and-chai-384ef05f32b2
     - https://mochajs.org/#getting-started
     - https://www.chaijs.com/guide/
- ~~ts-jest:~~
	 - ~~https://riptutorial.com/typescript/example/29207/jest--ts-jest~~
	 - ~~https://kulshekhar.github.io/ts-jest/~~
- tslint:
     - gulp-tslint: https://www.npmjs.com/package/gulp-tslint
     - https://spin.atomicobject.com/2017/06/05/tslint-linting-setup/
- Prettier:
     - https://prettier.io/
     - for Sublime: https://packagecontrol.io/packages/JsPrettier
- TypeDoc:
     - https://typedoc.org/
- Writing a library:
     - https://www.tsmean.com/articles/how-to-write-a-typescript-library/
     - https://www.tsmean.com/articles/how-to-write-a-typescript-library/local-consumer/
     - http://www.bradoncode.com/tutorials/browserify-tutorial-node-js/
- For making browser support less hacky:
     - https://stackoverflow.com/questions/30965909/how-to-remove-change-some-require-calls-when-using-browserify
     - -> https://github.com/rluba/browserify-global-shim
     - or https://github.com/thlorenz/browserify-shim

## Note on browser support

In order to make the library work on the browser we had to make a few not so pretty hacks.
We are using browserify to bundle the files and get around the *require* problem on the browser - however the mcl-wasm library is already ready for use in the browser and *doesn't like* being browserified again.

The main problem is that the `mcl.js` script tests whether it is being run in the browser or in nodejs. And in the browser it fetches the `.wasm` file, which browserify does not pack. Just making the `.wasm` file available does not work either. This happens because there are `require` commands that use a variable in the package name, and since browserify cannot resolve these `require`s statically, the resulting bundle crashes.

So here are the steps we took to make it work:
1. First we excluded `mcl-wasm` from the browserify bundle as there is no use in having it there.
2. Now we need to have all the files available when a page is loading - *mcl.js*, *mcl_c.js* and *mcl_c.wasm* - as they are not inside the bundle. So we copy them to the *browser* directory.
3. We remove all the `var mcl = require("mcl-wasm");` lines of code from the bundle. This way, the *mcl* variable corresponds to the one declared in the `mcl.js` file. Otherwise, if we keep those lines, the *mcl* variable is set to `undefined`.
4. Finally, the scripts *bundle.js*, *mcl.js* and *mcl_c.js*, need to be imported directly in the html page.

The first three steps can be completed automatically by running `gulp browser`.
