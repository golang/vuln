// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Program to generate false-positive CVE records.

// This requires a local copy of the cvelist repo:
//     git clone https://github.com/CVEProject/cvelist
// Then run this program with the path to the repo as argument.

//go:build ignore
// +build ignore

package main

import (
	"bytes"
	"fmt"
	"go/format"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"text/template"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/jba/printsrc"
	"golang.org/x/vuln/internal/gitrepo"
	"golang.org/x/vuln/internal/worker"
	"golang.org/x/vuln/internal/worker/store"
)

// The CVEs marked "false-positive" in triaged-cve-list,
// including both true false positives and CVEs that are
// covered by a Go vulndb report.
var falsePositiveIDs = []string{
	"CVE-2013-2124",
	"CVE-2013-2233",
	"CVE-2014-0177",
	"CVE-2014-3498",
	"CVE-2014-3971",
	"CVE-2014-4657",
	"CVE-2014-4658",
	"CVE-2014-4659",
	"CVE-2014-4660",
	"CVE-2014-4678",
	"CVE-2014-4966",
	"CVE-2014-4967",
	"CVE-2014-8178",
	"CVE-2014-8179",
	"CVE-2014-8682",
	"CVE-2014-9938",
	"CVE-2015-5237",
	"CVE-2015-5250",
	"CVE-2015-6240",
	"CVE-2015-7082",
	"CVE-2015-7528",
	"CVE-2015-7545",
	"CVE-2015-7561",
	"CVE-2015-8222",
	"CVE-2015-8945",
	"CVE-2015-9258",
	"CVE-2015-9259",
	"CVE-2015-9282",
	"CVE-2016-0216",
	"CVE-2016-1133",
	"CVE-2016-1544",
	"CVE-2016-1587",
	"CVE-2016-1905",
	"CVE-2016-1906",
	"CVE-2016-2160",
	"CVE-2016-2183",
	"CVE-2016-2315",
	"CVE-2016-2324",
	"CVE-2016-3096",
	"CVE-2016-3711",
	"CVE-2016-4817",
	"CVE-2016-4864",
	"CVE-2016-6349",
	"CVE-2016-6494",
	"CVE-2016-7063",
	"CVE-2016-7064",
	"CVE-2016-7075",
	"CVE-2016-7569",
	"CVE-2016-7835",
	"CVE-2016-8579",
	"CVE-2016-9274",
	"CVE-2016-9962",
	"CVE-2017-1000056",
	"CVE-2017-1000069",
	"CVE-2017-1000070",
	"CVE-2017-1000420",
	"CVE-2017-1000459",
	"CVE-2017-1000492",
	"CVE-2017-1002100",
	"CVE-2017-1002101",
	"CVE-2017-1002102",
	"CVE-2017-10868",
	"CVE-2017-10869",
	"CVE-2017-10872",
	"CVE-2017-10908",
	"CVE-2017-14178",
	"CVE-2017-14623",
	"CVE-2017-14992",
	"CVE-2017-15104",
	"CVE-2017-16539",
	"CVE-2017-17697",
	"CVE-2017-2428",
	"CVE-2017-7297",
	"CVE-2017-7481",
	"CVE-2017-7550",
	"CVE-2017-7860",
	"CVE-2017-7861",
	"CVE-2017-8359",
	"CVE-2017-9431",
	"CVE-2018-0608",
	"CVE-2018-1000400",
	"CVE-2018-1000538",
	"CVE-2018-1000803",
	"CVE-2018-1000816",
	"CVE-2018-1002100",
	"CVE-2018-1002101",
	"CVE-2018-1002102",
	"CVE-2018-1002103",
	"CVE-2018-1002104",
	"CVE-2018-1002105",
	"CVE-2018-1002207",
	"CVE-2018-10055",
	"CVE-2018-10856",
	"CVE-2018-10892",
	"CVE-2018-10937",
	"CVE-2018-1098",
	"CVE-2018-1099",
	"CVE-2018-12099",
	"CVE-2018-12608",
	"CVE-2018-12678",
	"CVE-2018-12976",
	"CVE-2018-14474",
	"CVE-2018-15178",
	"CVE-2018-15192",
	"CVE-2018-15193",
	"CVE-2018-15598",
	"CVE-2018-15664",
	"CVE-2018-15747",
	"CVE-2018-15869",
	"CVE-2018-16316",
	"CVE-2018-16359",
	"CVE-2018-16398",
	"CVE-2018-16409",
	"CVE-2018-16733",
	"CVE-2018-16859",
	"CVE-2018-16876",
	"CVE-2018-17031",
	"CVE-2018-17456",
	"CVE-2018-17572",
	"CVE-2018-18264",
	"CVE-2018-18553",
	"CVE-2018-18623",
	"CVE-2018-18624",
	"CVE-2018-18625",
	"CVE-2018-18925",
	"CVE-2018-18926",
	"CVE-2018-19114",
	"CVE-2018-19148",
	"CVE-2018-19184",
	"CVE-2018-19295",
	"CVE-2018-19333",
	"CVE-2018-19367",
	"CVE-2018-19466",
	"CVE-2018-19653",
	"CVE-2018-19786",
	"CVE-2018-19793",
	"CVE-2018-20303",
	"CVE-2018-20421",
	"CVE-2018-20699",
	"CVE-2018-20744",
	"CVE-2018-21034",
	"CVE-2018-21233",
	"CVE-2018-7575",
	"CVE-2018-7576",
	"CVE-2018-7577",
	"CVE-2018-8825",
	"CVE-2018-9057",
	"CVE-2019-1000002",
	"CVE-2019-1002100",
	"CVE-2019-1002101",
	"CVE-2019-1010003",
	"CVE-2019-1010261",
	"CVE-2019-1010275",
	"CVE-2019-1010314",
	"CVE-2019-10152",
	"CVE-2019-10156",
	"CVE-2019-10165",
	"CVE-2019-10200",
	"CVE-2019-1020009",
	"CVE-2019-1020014",
	"CVE-2019-1020015",
	"CVE-2019-10217",
	"CVE-2019-10223",
	"CVE-2019-10743",
	"CVE-2019-11043",
	"CVE-2019-11228",
	"CVE-2019-11229",
	"CVE-2019-11243",
	"CVE-2019-11244",
	"CVE-2019-11245",
	"CVE-2019-11246",
	"CVE-2019-11247",
	"CVE-2019-11248",
	"CVE-2019-11249",
	"CVE-2019-11251",
	"CVE-2019-11252",
	"CVE-2019-11255",
	"CVE-2019-11328",
	"CVE-2019-11405",
	"CVE-2019-11471",
	"CVE-2019-11502",
	"CVE-2019-11503",
	"CVE-2019-11576",
	"CVE-2019-11641",
	"CVE-2019-11881",
	"CVE-2019-11938",
	"CVE-2019-12291",
	"CVE-2019-12452",
	"CVE-2019-12494",
	"CVE-2019-12618",
	"CVE-2019-12995",
	"CVE-2019-12999",
	"CVE-2019-13068",
	"CVE-2019-13126",
	"CVE-2019-13139",
	"CVE-2019-13915",
	"CVE-2019-14243",
	"CVE-2019-14255",
	"CVE-2019-14271",
	"CVE-2019-14544",
	"CVE-2019-14846",
	"CVE-2019-14864",
	"CVE-2019-14904",
	"CVE-2019-14940",
	"CVE-2019-14993",
	"CVE-2019-15043",
	"CVE-2019-15119",
	"CVE-2019-15225",
	"CVE-2019-15226",
	"CVE-2019-15562",
	"CVE-2019-15716",
	"CVE-2019-16060",
	"CVE-2019-16097",
	"CVE-2019-16146",
	"CVE-2019-16214",
	"CVE-2019-16355",
	"CVE-2019-16778",
	"CVE-2019-16919",
	"CVE-2019-18466",
	"CVE-2019-18657",
	"CVE-2019-18801",
	"CVE-2019-18802",
	"CVE-2019-18817",
	"CVE-2019-18836",
	"CVE-2019-18838",
	"CVE-2019-18923",
	"CVE-2019-19023",
	"CVE-2019-19025",
	"CVE-2019-19026",
	"CVE-2019-19029",
	"CVE-2019-19316",
	"CVE-2019-19335",
	"CVE-2019-19349",
	"CVE-2019-19350",
	"CVE-2019-19724",
	"CVE-2019-19922",
	"CVE-2019-20329",
	"CVE-2019-20372",
	"CVE-2019-20377",
	"CVE-2019-20894",
	"CVE-2019-20933",
	"CVE-2019-25014",
	"CVE-2019-3552",
	"CVE-2019-3553",
	"CVE-2019-3558",
	"CVE-2019-3559",
	"CVE-2019-3565",
	"CVE-2019-3826",
	"CVE-2019-3828",
	"CVE-2019-3841",
	"CVE-2019-3990",
	"CVE-2019-5736",
	"CVE-2019-6035",
	"CVE-2019-8336",
	"CVE-2019-8400",
	"CVE-2019-9547",
	"CVE-2019-9635",
	"CVE-2019-9764",
	"CVE-2019-9900",
	"CVE-2019-9901",
	"CVE-2019-9946",
	"CVE-2020-10660",
	"CVE-2020-10661",
	"CVE-2020-10685",
	"CVE-2020-10691",
	"CVE-2020-10696",
	"CVE-2020-10706",
	"CVE-2020-10712",
	"CVE-2020-10715",
	"CVE-2020-10749",
	"CVE-2020-10750",
	"CVE-2020-10752",
	"CVE-2020-10763",
	"CVE-2020-10944",
	"CVE-2020-11008",
	"CVE-2020-11012",
	"CVE-2020-11013",
	"CVE-2020-11053",
	"CVE-2020-11080",
	"CVE-2020-11091",
	"CVE-2020-11110",
	"CVE-2020-11498",
	"CVE-2020-11576",
	"CVE-2020-11710",
	"CVE-2020-11767",
	"CVE-2020-12118",
	"CVE-2020-12245",
	"CVE-2020-12278",
	"CVE-2020-12279",
	"CVE-2020-12283",
	"CVE-2020-12458",
	"CVE-2020-12459",
	"CVE-2020-12603",
	"CVE-2020-12604",
	"CVE-2020-12605",
	"CVE-2020-12757",
	"CVE-2020-12758",
	"CVE-2020-12797",
	"CVE-2020-13170",
	"CVE-2020-13223",
	"CVE-2020-13246",
	"CVE-2020-13250",
	"CVE-2020-13401",
	"CVE-2020-13430",
	"CVE-2020-13449",
	"CVE-2020-13450",
	"CVE-2020-13451",
	"CVE-2020-13452",
	"CVE-2020-13597",
	"CVE-2020-13788",
	"CVE-2020-13794",
	"CVE-2020-14144",
	"CVE-2020-14306",
	"CVE-2020-14330",
	"CVE-2020-14332",
	"CVE-2020-14958",
	"CVE-2020-15104",
	"CVE-2020-15112",
	"CVE-2020-15113",
	"CVE-2020-15114",
	"CVE-2020-15115",
	"CVE-2020-15127",
	"CVE-2020-15129",
	"CVE-2020-15136",
	"CVE-2020-15157",
	"CVE-2020-15184",
	"CVE-2020-15185",
	"CVE-2020-15186",
	"CVE-2020-15187",
	"CVE-2020-15190",
	"CVE-2020-15191",
	"CVE-2020-15192",
	"CVE-2020-15193",
	"CVE-2020-15194",
	"CVE-2020-15195",
	"CVE-2020-15196",
	"CVE-2020-15197",
	"CVE-2020-15198",
	"CVE-2020-15199",
	"CVE-2020-15200",
	"CVE-2020-15201",
	"CVE-2020-15202",
	"CVE-2020-15203",
	"CVE-2020-15204",
	"CVE-2020-15205",
	"CVE-2020-15206",
	"CVE-2020-15207",
	"CVE-2020-15208",
	"CVE-2020-15209",
	"CVE-2020-15210",
	"CVE-2020-15211",
	"CVE-2020-15212",
	"CVE-2020-15213",
	"CVE-2020-15214",
	"CVE-2020-15223",
	"CVE-2020-15233",
	"CVE-2020-15234",
	"CVE-2020-15254",
	"CVE-2020-15257",
	"CVE-2020-15265",
	"CVE-2020-15266",
	"CVE-2020-15391",
	"CVE-2020-16248",
	"CVE-2020-16250",
	"CVE-2020-16251",
	"CVE-2020-16844",
	"CVE-2020-1733",
	"CVE-2020-1734",
	"CVE-2020-1735",
	"CVE-2020-1736",
	"CVE-2020-1737",
	"CVE-2020-1738",
	"CVE-2020-1739",
	"CVE-2020-1740",
	"CVE-2020-1746",
	"CVE-2020-2023",
	"CVE-2020-2024",
	"CVE-2020-2025",
	"CVE-2020-2026",
	"CVE-2020-24263",
	"CVE-2020-24264",
	"CVE-2020-24303",
	"CVE-2020-24356",
	"CVE-2020-24359",
	"CVE-2020-24707",
	"CVE-2020-24708",
	"CVE-2020-24710",
	"CVE-2020-24711",
	"CVE-2020-24712",
	"CVE-2020-25017",
	"CVE-2020-25018",
	"CVE-2020-25201",
	"CVE-2020-25816",
	"CVE-2020-25989",
	"CVE-2020-26222",
	"CVE-2020-26240",
	"CVE-2020-26241",
	"CVE-2020-26242",
	"CVE-2020-26265",
	"CVE-2020-26266",
	"CVE-2020-26267",
	"CVE-2020-26268",
	"CVE-2020-26269",
	"CVE-2020-26270",
	"CVE-2020-26271",
	"CVE-2020-26276",
	"CVE-2020-26277",
	"CVE-2020-26278",
	"CVE-2020-26279",
	"CVE-2020-26283",
	"CVE-2020-26284",
	"CVE-2020-26290",
	"CVE-2020-26294",
	"CVE-2020-26521",
	"CVE-2020-26892",
	"CVE-2020-27151",
	"CVE-2020-27195",
	"CVE-2020-27534",
	"CVE-2020-27955",
	"CVE-2020-28053",
	"CVE-2020-28348",
	"CVE-2020-28349",
	"CVE-2020-28466",
	"CVE-2020-28914",
	"CVE-2020-28924",
	"CVE-2020-28991",
	"CVE-2020-29243",
	"CVE-2020-29244",
	"CVE-2020-29245",
	"CVE-2020-29510",
	"CVE-2020-29511",
	"CVE-2020-29662",
	"CVE-2020-35137",
	"CVE-2020-35138",
	"CVE-2020-35177",
	"CVE-2020-35453",
	"CVE-2020-35470",
	"CVE-2020-35471",
	"CVE-2020-36066",
	"CVE-2020-3996",
	"CVE-2020-4037",
	"CVE-2020-4053",
	"CVE-2020-5215",
	"CVE-2020-5233",
	"CVE-2020-5260",
	"CVE-2020-5300",
	"CVE-2020-5303",
	"CVE-2020-5415",
	"CVE-2020-6016",
	"CVE-2020-6017",
	"CVE-2020-6018",
	"CVE-2020-6019",
	"CVE-2020-7218",
	"CVE-2020-7219",
	"CVE-2020-7220",
	"CVE-2020-7665",
	"CVE-2020-7666",
	"CVE-2020-7669",
	"CVE-2020-7955",
	"CVE-2020-7956",
	"CVE-2020-8551",
	"CVE-2020-8552",
	"CVE-2020-8553",
	"CVE-2020-8554",
	"CVE-2020-8555",
	"CVE-2020-8557",
	"CVE-2020-8558",
	"CVE-2020-8559",
	"CVE-2020-8563",
	"CVE-2020-8566",
	"CVE-2020-8569",
	"CVE-2020-8595",
	"CVE-2020-8659",
	"CVE-2020-8660",
	"CVE-2020-8661",
	"CVE-2020-8663",
	"CVE-2020-8664",
	"CVE-2020-8826",
	"CVE-2020-8827",
	"CVE-2020-8828",
	"CVE-2020-8843",
	"CVE-2020-8927",
	"CVE-2020-8929",
	"CVE-2020-9321",
	"CVE-2020-9329",
	"CVE-2021-20198",
	"CVE-2021-20199",
	"CVE-2021-20218",
	"CVE-2021-20291",
	"CVE-2021-21271",
	"CVE-2021-21284",
	"CVE-2021-21285",
	"CVE-2021-21287",
	"CVE-2021-21291",
	"CVE-2021-21296",
	"CVE-2021-21300",
	"CVE-2021-21303",
	"CVE-2021-21334",
	"CVE-2021-21362",
	"CVE-2021-21363",
	"CVE-2021-21364",
	"CVE-2021-21378",
	"CVE-2021-21390",
	"CVE-2021-21404",
	"CVE-2021-21411",
	"CVE-2021-21432",
	"CVE-2021-22538",
	"CVE-2021-23345",
	"CVE-2021-23347",
	"CVE-2021-23351",
	"CVE-2021-23357",
	"CVE-2021-23827",
	"CVE-2021-25313",
	"CVE-2021-25834",
	"CVE-2021-25835",
	"CVE-2021-25836",
	"CVE-2021-25837",
	"CVE-2021-26921",
	"CVE-2021-26923",
	"CVE-2021-26924",
	"CVE-2021-27098",
	"CVE-2021-27099",
	"CVE-2021-27358",
	"CVE-2021-27375",
	"CVE-2021-27935",
	"CVE-2021-27940",
	"CVE-2021-28361",
	"CVE-2021-28378",
	"CVE-2021-28681",
	"CVE-2021-28954",
	"CVE-2021-28955",
	"CVE-2021-29136",
	"CVE-2021-29271",
	"CVE-2021-29272",
	"CVE-2021-29417",
	"CVE-2021-29651",
	"CVE-2021-29652",
	"CVE-2021-3344",
	"CVE-2021-3382",
	"CVE-2021-3391",
}

// IDs that are covered by a Go vuln report, and the report ID.
var coveredIDs = map[string]string{
	"CVE-2020-15112": "GO-2020-0005",
	"CVE-2020-29243": "GO-2021-0097",
	"CVE-2020-29244": "GO-2021-0097",
	"CVE-2020-29245": "GO-2021-0097",
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: gen_false_positives PATH_TO_LOCAL_REPO")
	}
	if err := run(os.Args[1]); err != nil {
		log.Fatal(err)
	}
}

func run(repoPath string) error {
	printer := printsrc.NewPrinter("golang.org/x/vuln/internal/worker")
	tmpl, err := template.New("").
		Funcs(template.FuncMap{"src": printer.Sprint}).
		Parse(fileTemplate)
	if err != nil {
		return err
	}
	repo, err := gitrepo.Open(repoPath)
	if err != nil {
		return err
	}
	crs, err := buildCVERecords(repo)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, crs); err != nil {
		return err
	}
	src, err := format.Source(buf.Bytes())
	if err != nil {
		return err
	}
	return ioutil.WriteFile("false_positive_records.gen.go", src, 0644)
}

func buildCVERecords(repo *git.Repository) ([]*store.CVERecord, error) {
	commit, err := repo.CommitObject(plumbing.NewHash(worker.FalsePositiveCommitHash))
	if err != nil {
		return nil, err
	}
	var crs []*store.CVERecord
	for _, id := range falsePositiveIDs {
		path := idToPath(id)
		cve, blobHash, err := worker.ReadCVEAtPath(commit, path)
		if err != nil {
			return nil, err
		}
		if cve.ID != id {
			return nil, fmt.Errorf("ID at path %s is %s", path, cve.ID)
		}
		cr := store.NewCVERecord(cve, path, blobHash)
		cr.CommitHash = worker.FalsePositiveCommitHash
		if reportID := coveredIDs[id]; reportID != "" {
			cr.TriageState = store.TriageStateHasVuln
			cr.TriageStateReason = reportID
		} else {
			cr.TriageState = store.TriageStateFalsePositive
			for _, r := range cve.References.Data {
				if r.URL != "" {
					cr.ReferenceURLs = append(cr.ReferenceURLs, r.URL)
				}
			}
		}
		crs = append(crs, cr)
	}
	return crs, nil
}

func idToPath(id string) string {
	words := strings.Split(id, "-")
	year := words[1]
	num := []byte(words[2])
	// Last three digits of number replaced by 'x'.
	for i := 1; i <= 3; i++ {
		num[len(num)-i] = 'x'
	}
	for len(num) < 4 {
		num = append([]byte{'0'}, num...)
	}
	return fmt.Sprintf("%s/%s/%s.json", year, num, id)
}

var fileTemplate = `
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Code generated by gen_false_positives.go; DO NOT EDIT.

package worker

import "golang.org/x/vuln/internal/worker/store"

var falsePositives = {{. | src}}
`
