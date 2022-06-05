#!/bin/sh
# The go-landlock tests are currently just a shell script. Running
# Landlock from within a regular Go test is harder to manage, as tests
# can interfere with each other.

enter () {
    printf "[Test] %60s" "$*"
}

success () {
    echo -e " \e[1;32m[ok]\e[0m"
}

fail () {
    echo -e " \e[1;31m[fail]\e[0m"
    echo
    echo "****************"
    echo $*
    echo "****************"
    echo
    echo "Direcory contents:"
    find .
    echo
    echo "Stdout:"
    cat stdout.txt
    echo
    echo "Stderr:"
    cat stderr.txt
    exit 1
}

shutdown() {
    rm -rf "${TMPDIR}"
}

expect_success() {
    if [ "$?" -ne 0 ]; then
        fail "Expected:" $*
    fi
    success
}

expect_failure() {
    if [ "$?" -eq 0 ]; then
        fail "Expected:" $*
    fi
    success
}

# Run
run() {
    "${CMD}" -v -ro /bin /usr $* >stdout.txt 2>stderr.txt
}

CMD="$(pwd)/main"

if [ ! -f "${CMD}" ]; then
    echo "Sandboxing command does not exist: ${CMD}"
    echo "Cannot run the tests."
    exit 1
fi

TMPDIR=$(mktemp -t -d go-landlock-test.XXXXXX)
echo "Running in ${TMPDIR}"
cd "${TMPDIR}"
trap shutdown EXIT

# Set up an initial environment:
mkdir -p foo
echo lolcat > foo/lolcat.txt

# Tests
enter "No sandboxing, read works"
/bin/cat foo/lolcat.txt > /dev/null
expect_success "reading file should have worked"

enter "No permissions, doing nothing succeeds"
run -- /bin/true
expect_success "doing nothing should succeed"

enter "No permissions, read fails"
run -- /bin/cat foo/lolcat.txt
expect_failure "should have failed to read file"

enter "Read permissions on dir (relative path), read works"
run -ro "foo" -- /bin/cat foo/lolcat.txt
expect_success "should have read the file"

enter "Read permissions on dir (full path), read works"
run -ro "${TMPDIR}/foo" -- /bin/cat foo/lolcat.txt
expect_success "should have read the file"

enter "File-read permissions on file, read works"
run -rofiles "foo/lolcat.txt" -- /bin/cat foo/lolcat.txt
expect_success "should have read the file"

enter "File-read permissions on dir, read works"
run -rofiles "foo" -- /bin/cat foo/lolcat.txt
expect_success "should have read the file"

enter "Read-only permissions on dir, creating file fails"
run -ro "foo" -- /bin/touch foo/fail
expect_failure "should not be able to create file"

enter "RW permissions on dir, creating file succeeds"
run -rw "foo" -- /bin/touch foo/succeed
expect_success "should be able to create file"

enter "Read-only permissions on dir, removing file fails"
run -ro "foo" -- /bin/rm foo/succeed
expect_failure "should not be able to remove file"

enter "RW permissions on dir, removing file succeeds"
run -rw "foo" -- /bin/rm foo/succeed
expect_success "should be able to remove file"

enter "Read-only permissions on dir, mkfifo fails"
run -ro "foo" -- /bin/mkfifo foo/fifo
expect_failure "should not be able to create file"

enter "RW permissions on dir, mkfifo succeeds"
run -rw "foo" -- /bin/mkfifo foo/fifo
expect_success "should be able to create file"
rm foo/fifo

echo
echo "All tests executed."
