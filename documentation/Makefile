#
# Makefile to generate epydoc documentation for the MyProxy Client Package
#
# NERC DataGrid Project
#
# @author P J Kershaw 15/12/08
#

# @copyright: (C) 2008 STFC
#
# @license: BSD - See LICENSE file in top-level directory
#
# $Id$

# Generate HTML from embedded epydoc text in source code.
EPYDOC=epydoc
EPYDOC_OUTDIR=.
EPYDOC_NAME='MyProxy Client'
EPYDOC_LOGFILE=epydoc.log
EPYDOC_FRAMES_OPT=--no-frames
epydoc:
	${EPYDOC} ../myproxy -o ${EPYDOC_OUTDIR} --name ${EPYDOC_NAME} \
	${EPYDOC_FRAMES_OPT} --include-log --graph=all -v > ${EPYDOC_LOGFILE}
	
clean:
	rm -f *.txt *.html *.gif