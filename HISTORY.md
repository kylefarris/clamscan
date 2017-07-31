# Changes

This file is a manually maintained list of changes for each release. Feel free
to add your changes here when sending pull requests. Also send corrections if
you spot any mistakes.

### 0.2.1

* ClamAV returns an exit code 1 when it detects a virus but `exec` was interpreting that response as an error. Checking the response with type-sensitive equivalence resolves this bug.

### 0.2.2

* Fixed documentation

### 0.4.0 (2014-11-19)

* Corrected the installation instructions for `clamav`. Thank you @jshamley!
* Fixed major bug preventing the `scan_dir` method from working properly
* Corrected documentation describing how to instantiate this module.

### 0.5.0 (2014-12-19)

* Deprecated the `quarantine_path` option. Please only use `quarantine_infected` for now on.
* Updated documentation to reflect above change.

### 0.6.0 (2015-01-02)

__NOTE:__ There are some breaking changes on this release. Since this is still a pre-version 1 release, I decided to only do a minor bump to 0.4.0

* The ability to run "forked" instances of `clamscan` has been removed because of irregularities with different systems--namely if you had `max_forks` set to 3, it would sometimes only scan the first or last file in the group... not good.
* Added the ability to use `clamdscan`. This ultimately negates the downside of removing the forking capability mentioned in item one. This is a really big improvement (many orders of magnitude) if your system has access to the `clamdscan` daemon.
* Added a `file_list` option allowing one to specify a text file that lists (one per line) paths to files to be scanned. This is great if you need to scan hundreds or thousands of random files.
* `clam_path` option has been moved to `clam.path`
* `db` option has been moved to `clam.db`
* `scan_archives` option has been moved to `clam.scan_archives`
* `scan_files` now supports directories as well and will obey your `scan_recursively` option.

### 0.6.1 (2015-01-05)

* Updated description in package.json file.

### 0.6.2 (2015-01-05)

* Fixed major bug in the scan_files method that was causing it to only scan half the files passed to it.

### 0.6.3 (2015-01-05)

* Removed the unnecessary "index_old.js" file put there for reference during the 0.5.0 -> 0.6.0 semi-rewrite.

### 0.6.4 (2015-01-26)

* Fixed error messages

### 0.7.0 (2015-06-01)

* Fixed a bug caused by not passing a `file_cb` paramter to the `scan_file` method. Thanks nicolaspeixoto!
* Added tests
* Fixed poor validation of method parameters
* Changed API of `scan_dir` such that the paramaters passed to the `end_cb` are different in certain defined situations. See the "NOTE" section of the `scan_dir` documentation for details.
* Changed `err` paramter in all callbacks from a simple string to a proper javascript `Error` object.
* Added documentation for how to use a file_list file for scanning.

### 0.7.1 (2015-06-05)

* Added node dependency of > 0.12 to `package.json` file

### 0.8.0 (2015-06-05)

* Removed item causing node > 0.12 dependency.
* Removed dependency of node > 0.12 in `package.json` file.

### 0.8.1 (2015-06-09)

* Fixed check for database file. Issue #6

### 0.8.2 (2015-08-14)

* Updated to `execFile` instead of `exec`
* Improved test suite

### 0.8.5 (2017-07-31)

* Added `get_clam_version` method
