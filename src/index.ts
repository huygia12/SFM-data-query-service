import moduleAlias from "module-alias";
moduleAlias.addAliases({
    "@": `${__dirname}`,
});
import loaders from "./loaders";

loaders();
