/** Private profile gate. Build/test only an isolated copy; synthetic signing authority is local to it. */
import {cp,mkdir,mkdtemp,readdir,rm} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {buildGatewayPackageFixture} from '../../../mcp-gateway/scripts/library-fixture.mjs';

const packageRoot=resolve(import.meta.dirname,'../..'),repositoryRoot=resolve(packageRoot,'../..');
const [major,minor]=process.versions.node.split('.').map(Number);
if(process.platform!=='linux'||major<22||major===22&&minor<16)throw new Error('PRIVACY_CI_REQUIRES_LINUX_NODE_22_16');
if(!process.env.AIDR_PYTHON||!process.env.AIDR_TEST_PYTHON)throw new Error('PRIVACY_CI_REQUIRES_PHYSICAL_PYTHON');
const run=(command,args,cwd,env=process.env)=>{
 const result=spawnSync(command,args,{cwd,env,stdio:'inherit',windowsHide:true});
 if(result.error)throw result.error;if(result.status!==0)throw new Error('PRIVACY_CI_COMMAND_FAILED');
};
const root=await mkdtemp(join(tmpdir(),'aidr-private-ci-')),work=join(root,'private');
const runNodeTests=(files,env=process.env)=>{
 const result=spawnSync(process.execPath,['--test','--test-concurrency=1','--test-reporter=tap',...files],{cwd:work,env,encoding:'utf8',maxBuffer:16777216,windowsHide:true});
 process.stdout.write(result.stdout??'');process.stderr.write(result.stderr??'');
 if(result.error)throw result.error;if(result.status!==0)throw new Error('PRIVACY_CI_NODE_FAILED');
 const summary=(result.stdout??'').replaceAll('\r\n','\n').match(/\n# tests (\d+)\n# suites \d+\n# pass (\d+)\n# fail (\d+)\n# cancelled (\d+)\n# skipped (\d+)\n# todo (\d+)\n/);
 if(!summary||Number(summary[1])<1||summary[1]!==summary[2]||summary.slice(3).some(value=>Number(value)!==0))throw new Error('PRIVACY_CI_NODE_INCOMPLETE');
};
try{
 await mkdir(work);await mkdir(join(work,'reports','browser'),{recursive:true});
 // Explicit bounded source roots: never copy ignored model/runtime/corpus staging in reports.
 for(const name of ['src','extension','tests','parsers','ner','models','fixtures','native','vision','portal','scripts','examples','deployment']){
  await cp(join(packageRoot,name),join(work,name),{recursive:true,filter:path=>!['node_modules','dist','__pycache__','chrome'].includes(path.split(/[\\/]/).at(-1))});
 }
 for(const name of ['package.json','tsconfig.json','README.md','SECURITY.md','NOTICE.md','CHANGELOG.md'])await cp(join(packageRoot,name),join(work,name));
 const compiler=createRequire(import.meta.url).resolve('typescript/bin/tsc');
 run(process.execPath,[compiler,'-p',join(packageRoot,'tsconfig.json'),'--outDir',join(work,'dist'),'--sourceMap','false','--declarationMap','false'],packageRoot);
 run(process.execPath,[compiler,'-p',join(packageRoot,'extension','tsconfig.json'),'--noEmit'],packageRoot);
 run(process.execPath,[join(packageRoot,'scripts','build-extension.mjs')],work);
 run(process.execPath,[join(repositoryRoot,'scripts','check-no-sourcemaps.mjs'),join(work,'dist')],work);
 // Installer, corpus selection and artifact/offset tests use only the Python standard library.
 run(process.env.AIDR_PYTHON,['-I','-S','-c',"import unittest,sys; suite=unittest.defaultTestLoader.discover('ner',pattern='test_*.py'); result=unittest.TextTestRunner(verbosity=2).run(suite); sys.exit(not (result.testsRun>0 and result.wasSuccessful() and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses))"],work);
 const files=[];
 for(const dir of ['tests','tests/visual','tests/browser','tests/native','tests/enterprise','tests/platform']){
  files.push(...(await readdir(join(work,dir))).filter(name=>name.endsWith('.test.mjs')).sort().map(name=>join(dir,name)));
 }
 runNodeTests(files);
 // Fresh installed package, ephemeral keys and isolated HOME. Never edit delivered signer trust.
 const fixture=await buildGatewayPackageFixture(root);
 runNodeTests(['tests/integration/mcp-installed.test.mjs'],fixture.environment);
}finally{await rm(root,{recursive:true,force:true});}
