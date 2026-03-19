if [ "${UID}" != "0" ]; then
	sudo $0 $@
	exit $?
fi

ln -s libtpm2tss.so /usr/lib64/engines-3/tpm2.so

