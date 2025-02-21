def diff2policy(new, old):
    res = {}
    for claim in set(new).intersection(set(old)):
        if new[claim] == old[claim]:
            continue
        else:
            res[claim] = {'value': new[claim]}

    for claim in set(new).difference(set(old)):
        if claim in ['contacts']:
            res[claim] = {'add': new[claim]}
        else:
            res[claim] = {'value': new[claim]}

    return res