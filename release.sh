Project=$(basename `pwd`)
Version=$(cat ngx_http_subrange_module.h  | grep NGX_HTTP_SUBRANGE_VERSION | awk '{print $NF}')
PackageDir="$Project"-"$Version"
cd ..
rm -rf $PackageDir
cp -r $Project $PackageDir
tar -zcf "$PackageDir".tar.gz $PackageDir
