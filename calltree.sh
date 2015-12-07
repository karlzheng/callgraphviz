#!/bin/bash

touch ~/calltree.deny

#use cscope to build reference files (./cscope.out by default, use set_graphdb to override name or location)
set_graphdb() { export GRAPHDB=$1; }
unset_graphdb() { unset GRAPHDB; }
build_graphdb() { cscope -bkRu ${GRAPHDB:+-f $GRAPHDB} && echo Created ${GRAPHDB:-cscope.out}...; }

# cscope queries
fdefine() { cscope ${GRAPHDB:+-f $GRAPHDB} -d -L1 $1; }
callees() { cscope ${GRAPHDB:+-f $GRAPHDB} -d -L2 $1; }
callers() { cscope ${GRAPHDB:+-f $GRAPHDB} -d -L3 $1; }

# given a set of function names, find out how they're related
filter_edges() { local sym cscope_line
    while read -a sym; do
        fdefine $sym | while read -a cscope_line; do
            grep -wq ${cscope_line[1]} ${1:-<(echo)} &&
            printf "${cscope_line[1]}\t[href=\"${cscope_line[0]}:${cscope_line[2]}\"]\t/*fdefine*/\n"
        done
        callees $sym | while read -a cscope_line; do
            grep -wq ${cscope_line[1]} ${1:-<(echo)} &&
            printf "$sym->${cscope_line[1]}\t[label=\"${cscope_line[0]}:${cscope_line[2]}\"]\t/*callee*/\n"
        done
        callers $sym | while read -a cscope_line; do
            grep -wq ${cscope_line[1]} ${1:-<(echo)} &&
            printf "${cscope_line[1]}->$sym\t[label=\"${cscope_line[0]}:${cscope_line[2]}\"]\t/*caller*/\n"
        done
    done
}

# present list of function names to filter_edges properly
edges() { local tfile=/tmp/edges.$RANDOM
    cat > $tfile
    filter_edges $tfile <$tfile
    rm $tfile
}

# append unknown symbol names out of lines of cscope output
filter_cscope_lines() { local cscope_line
    while read -a cscope_line; do
        grep -wq ${cscope_line[1]} ${1:-/dev/null} || echo ${cscope_line[1]}
    done 
}

# given a set of function names piped in, help spit out all their callers or callees that aren't already in the set
descend() { local symbol cnt=0 max=${3:-0}
    while read -a symbol; do
	if [ $max -ne 0 -a $cnt -eq $max ]; then return 0 ; fi
	cnt=$(($cnt+1))
        $1 $symbol | filter_cscope_lines $2
    done
}

# discover functions upstream of initial set
all_callers() { local tfile=/tmp/all_callers.$RANDOM
    cat ${1:+<(echo $1)} > $tfile
    descend callers $tfile ${2:-0} <$tfile >>$tfile
    cat $tfile; rm $tfile
}

# discover functions downstream of initial set
all_callees() { local tfile=/tmp/all_callees.$RANDOM
    cat ${1:+<(echo $1)} > $tfile
    descend callees $tfile ${2:-0}<$tfile >>$tfile
    cat $tfile; rm $tfile
}

# intersection of all_callees(a) and all_callers(b)
call_tree() { local tfile=/tmp/graph_filter.$RANDOM
    all_callees $1 | sort -u > $tfile
    comm -12 $tfile <(all_callers $2 | sort -u);
    rm $tfile
}

# all functions downstream of callers of argument
all_callerees() { callers $1 | filter_cscope_lines | all_callees; }

# odd experimental set of calls that might help spot potential memory leaks
call_leaks() { local tfile=/tmp/graph_filter.$RANDOM
    all_callerees $1 | sort -u > $tfile
    comm -2 $tfile <(all_callers $2 | sort -u)
    rm $tfile
}

# all the ways to get from (a,b,...z) to (a,b,...z)
call_graph() { for a; do for b; do if [ $a != $b ]; then call_tree $a $b; fi; done; done; }

# wrap dot-format node and edge info with dot-format whole-graph description
graph() { printf "digraph iftree {\ngraph [rankdir=LR, concentrate=true];\nnode [shape=record];\nedge [];\n"; cat | sort -u; printf "}\n"; }

# filter out unwanted (as specified in “~/calltree.deny”) and/or unnecessary edges
graph_filter() { local tfile=/tmp/graph_filter.$RANDOM
    cat > $tfile
    grep fdefine $tfile
    grep $1 $tfile | grep -vf ~/calltree.deny | cut -f1,3
    rm $tfile
}

# how to invoke zgrviewer as a viewer
zgrviewer() { ~/bin/zgrviewer -Pdot $*; }
# how to invoke xfig as a viewer
figviewer() { xfig <(dot -Tfig $*); }

# specify a viewer
ctviewer() { xdg-open $*; }

# add color to specified nodes
colornodes() { (cat; for x in $@; do echo "$x [color=red]"; done;) }

# generate dot files
_upstream() { all_callers $1 $2 | edges | graph_filter ${3:-caller} | colornodes $1 | graph; }
_downstream() { all_callees $1 $2 | edges | graph_filter ${3:-callee} | colornodes $1 | graph; }
_subgraph() { call_tree $1 $2 | edges | graph_filter ${3:-callee} | colornodes $1 $2 | graph; }
_relate() { call_graph $@ | edges | graph_filter callee | colornodes $@ | graph; }
_leaks() { call_leaks $1 $2 | edges | graph_filter ${3:-callee} | colornodes $1 $2 | graph; }

# generate dot files and invoke ctviewer
upstream() { _upstream $@ > /tmp/tfile; ctviewer /tmp/tfile; }
downstream() { _downstream $@ > /tmp/tfile; ctviewer /tmp/tfile; }
subgraph() { _subgraph $@ > /tmp/tfile; ctviewer /tmp/tfile;}
relate() { _relate $@ > /tmp/tfile; ctviewer /tmp/tfile; }
leaks() { _leaks $@ > /tmp/tfile; ctviewer /tmp/tfile; }

# dot file conversions
dot2png() { dot -Tpng -o $1; }
dot2jpg() { dot -Tjpg -o $1; }
dot2html() { dot -Tpng -o $1.png -Tcmapx -o $1.map; (echo "<IMG SRC="$1.png" USEMAP="#iftree" />"; cat $1.map)  > $1.html; }

$1 "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"
