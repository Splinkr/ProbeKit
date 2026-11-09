"""Independent scoring/integrity regressions; fixtures are not experimental runs."""
from copy import deepcopy
import hashlib
from pathlib import Path
import zipfile

import pytest

from experiments.evaluation.common import put, load, seal, verify_seal, confined, encoded, ROOT
from experiments.evaluation.metrics import cell, summarize, grouped, repeatability
from experiments.evaluation.compare_baseline import predict


def row(outcome="confirmed", truth="vulnerable", **extra):
    return dict(evaluation_id="fixture",case_id="S01",condition="default",repetition=1,unit_id="S01a",
                module="sqli",domain="controlled",stratum="principal",truth=truth,outcome=outcome,
                baseline="positive",wall_seconds=1,requests=10, **extra)


@pytest.mark.parametrize('truth,outcome,module,expected', [
    ('vulnerable','confirmed','sqli','TP'),('safe','confirmed','sqli','FP'),
    ('safe','not_detected','exposure','TN'),('vulnerable','not_detected','sqli','FN'),
    ('safe','reflected_safe','xss','TN'),('vulnerable','reflected_safe','xss','FN'),
    ('vulnerable','suspected','xss','suspected'),('safe','inconclusive','sqli','inconclusive'),
    ('safe','not_evaluated','exposure','not_evaluated'),('mitigated','confirmed','xss','outside_binary')])
def test_strict_cells(truth,outcome,module,expected):
    assert cell(truth,outcome,module)==expected


def test_exact_metrics_and_no_rounding_or_abstention_conversion():
    data=[row(),row('confirmed','safe'),row('not_detected','safe'),row('not_detected'),
          row('suspected'),row('inconclusive'),row('not_evaluated')]
    metrics=summarize(data)
    assert metrics['precision']['value']==.5
    assert metrics['recall']['value']==.5
    assert metrics['specificity']['value']==.5
    assert metrics['coverage']['value']==6/7
    assert metrics['confirmation_yield']['value']==1/5
    assert metrics['inconclusive_rate']['value']==1/6


def test_mitigated_outcomes_are_counted_without_binary_assignment():
    data = [row('suspected', 'mitigated'), row('inconclusive', 'mitigated')]
    metrics = summarize(data)
    assert metrics['counts']['outside_binary'] == 2
    assert all(metrics['counts'][key] == 0 for key in ('TP', 'FP', 'TN', 'FN'))
    assert metrics['observed'] == {'suspected': 1, 'inconclusive': 1}
    assert metrics['suspected_rate']['value'] == .5
    assert metrics['inconclusive_rate']['value'] == .5
    assert metrics['precision']['value'] is None


@pytest.mark.parametrize('data',[[],[row('suspected')],[row('inconclusive')],[row('not_evaluated')]])
def test_undefined_denominators_remain_null(data):
    result=summarize(data)
    assert result['precision']['value'] is None and result['recall']['value'] is None
    assert result['precision']['undefined_reason']=='denominator_zero'


def test_duplicate_rows_rejected_and_unknown_not_binary():
    with pytest.raises(ValueError):grouped([row(),row()])
    assert grouped([row(truth='unknown')])==[]
    with pytest.raises(ValueError):cell('safe','reflected_safe','sqli')


def test_repetition_does_not_impute_missing_runs():
    rows=[row(),row()];rows[1]['repetition']=2;rows[1]['outcome']='not_evaluated'
    result=repeatability(rows)[0]
    assert result['evaluated']==1 and result['modal_frequency'] is None
    assert not result['all_three_consistent'] and result['requests']['sample_stdev'] is None


@pytest.mark.parametrize('state', ['missing', 'unclassified', 'inconclusive'])
def test_partial_snapshot_preserves_inconclusive_without_inventing_a_negative(state):
    from experiments.evaluation.extract import extract
    unit=dict(unit_id='U01',module='sqli',truth='vulnerable',stratum='principal',parameter='q',file_path=None)
    case=dict(units=[unit])
    job=dict(evaluation_id='fixture',case_id='C01',condition='default',repetition=1)
    assessment={'outcome':'inconclusive','checks':{}} if state=='inconclusive' else None
    item=dict(parameter='q',assessment=assessment,evidence_request_ids=[])
    data=dict(mode='sqli',parameter_results=[] if state=='missing' else [item],collection_status='incomplete')
    actual=extract(case,job,dict(reason='observed'),data)[0]
    assert actual['outcome']==('inconclusive' if state=='inconclusive' else 'not_evaluated')
    assert actual['reason']==('observed' if state=='inconclusive' else 'assessment_missing')
    if state!='inconclusive':
        assert actual['requests'] is None and actual['browser_confirmed'] is None


def test_timing_excludes_integrations_and_deduplicates_multi_units():
    from experiments.evaluation.generate_report import timing_points
    a=row();b={**row(), 'unit_id':'S01b'};integration={**row(),'case_id':'I01','domain':'integration','wall_seconds':25}
    assert len(timing_points([a,b,integration]))==1
    assert timing_points([a,b,integration])[0]['wall_seconds']==1


def observation(i,size=5):
    return dict(request_id=i,status_code=200,size_bytes=size,body_sha256='a'*64)


@pytest.mark.parametrize('complete,ids,expected',[(True,[1,2],'negative'),(False,[1,2],'inconclusive'),(True,[1,3],'inconclusive')])
def test_baseline_evidence_completeness(complete,ids,expected):
    assert predict([observation(1),observation(2)],1,ids,complete)==expected


def test_baseline_only_observations_determine_prediction():
    observations=[observation(1),observation(2,6)]
    assert predict(observations,1,[1,2],True)=='positive'
    # No API parameter can supply a label, URL, case name or assessment.
    import inspect
    assert set(inspect.signature(predict).parameters)=={'observations','reference_id','required_ids','complete'}


def test_catalog_truth_from_sources_not_assessments():
    from experiments.evaluation.common import CASES, digest
    catalog=load(CASES)
    assert len(catalog['cases'])==45
    assert sum(len(c['conditions']) for c in catalog['cases'])*3==165
    direct=[c for c in catalog['cases'] if c.get('domain','controlled')=='controlled']
    assert sum(len(c['units'])*len(c['conditions'])*3 for c in direct)==195
    assert sum(c['budget']*len(c['conditions'])*3 for c in catalog['cases'])==2040
    for c in catalog['cases']:
        for unit in c['units']:
            assert unit['truth'] in {'safe','vulnerable','mitigated'}
            assert digest(ROOT/unit['oracle']['source'])==unit['oracle']['sha256']
            assert 'assessment' not in unit['oracle']['source']


def test_exclusive_creation_and_seal_reject_tamper(tmp_path):
    p=put(tmp_path/'data.json',dict(value=1))
    with pytest.raises(FileExistsError):put(p,dict(value=2))
    seal(tmp_path);verify_seal(tmp_path)
    p.write_bytes(b'{}')
    with pytest.raises(ValueError):verify_seal(tmp_path)
    with pytest.raises(ValueError):confined(tmp_path,'../outside')


@pytest.mark.parametrize('fault',['run_id','snapshot_id','bytes'])
def test_extractor_rejects_wrong_identity_or_bytes(tmp_path,fault):
    from scanner.models import ScanReport
    from scanner.reporter import write_reports,manifest_path
    from experiments.evaluation.extract import verified
    report=ScanReport('http://127.0.0.1/','fixture',{})
    output=tmp_path/'full.json'
    write_reports(report,output,evidence_profile='restricted')
    pointer=manifest_path(output);manifest=load(pointer)
    result=dict(run_id=report.run_id,snapshot_id=manifest['snapshot_id'])
    if fault=='bytes':
        target=tmp_path/manifest['files']['technical']['path'];target.write_bytes(target.read_bytes()+b' ')
    else:result[fault]='wrong'
    with pytest.raises(ValueError):verified(pointer,result)


def test_archive_escape_is_rejected_before_extraction(tmp_path,monkeypatch):
    from experiments.evaluation import run_evaluation as runner
    archive=tmp_path/'bad.zip'
    with zipfile.ZipFile(archive,'w') as z:z.writestr('../escape','bad')
    monkeypatch.setattr(runner,'ARCHIVE',archive)
    monkeypatch.setattr(runner,'ARCHIVE_SHA',hashlib.sha256(archive.read_bytes()).hexdigest())
    with pytest.raises(ValueError):runner.clone_juice(tmp_path)
    assert not (tmp_path.parent/'escape').exists()


@pytest.mark.parametrize('mismatch', ['row_campaign', 'metric_analysis', 'registry_source'])
def test_partial_campaign_exports_without_network_or_secrets(tmp_path,monkeypatch,mismatch):
    from experiments.evaluation import run_evaluation as runner
    from experiments.evaluation import generate_report as generator
    from scanner.models import ScanReport,SqliAssessment,ParameterResult,ProbeEvidence,ResponseEvidence
    from scanner.reporter import write_reports,manifest_path
    monkeypatch.setattr('scanner.http_client.HttpClient.get',lambda *_:pytest.fail('Offline export accessed network'))
    campaign=runner.prepare(tmp_path/'campaigns')
    frozen=load(campaign/'campaign.json')
    job=frozen['jobs'][0]
    report=ScanReport('http://127.0.0.1/PRIVATE_URL?q=demo','2026-11-09T00:00:00+00:00',dict(samples=2),mode='sqli')
    report.finished_at='2026-11-09T00:00:01+00:00'
    report.assessment=SqliAssessment('confirmed',{'baseline_stable':True},'PRIVATE_RATIONALE',[],parameter='q')
    report.parameter_results=[ParameterResult('q','like',report.assessment,[1,2])]
    report.probes=[ProbeEvidence(1,'baseline_1','q','PRIVATE_PAYLOAD'),ProbeEvidence(2,'recovery','q','PRIVATE_PAYLOAD')]
    report.responses=[ResponseEvidence(i,report.target,report.started_at,200,'text/plain',5,'a'*64,1,b'PRIVATE_BODY') for i in [1,2]]
    output=campaign/'runs'/job['slot']/'full.json'
    write_reports(report,output,evidence_profile='restricted')
    pointer=manifest_path(output);data=load(pointer)
    put(output.parent/'result.json',dict(reason='observed',run_id=report.run_id,snapshot_id=data['snapshot_id'],manifest=pointer.relative_to(campaign).as_posix(),manifest_sha256=hashlib.sha256(pointer.read_bytes()).hexdigest(),requests=2,wall_seconds=1,return_code=0))
    seal(campaign)
    # Keep the public fixture package outside the repository.
    monkeypatch.setattr(generator,'ROOT',tmp_path)
    analysis=generator.analyze(campaign)
    public=generator.export(campaign,analysis)
    generator.verify(public)
    for p in public.rglob('*'):
        if p.is_file():
            assert not any(s in p.read_bytes() for s in [b'PRIVATE_URL',b'PRIVATE_PAYLOAD',b'PRIVATE_BODY',b'PRIVATE_RATIONALE'])
    rows=load(public/'analysis/rows.json')
    assert sum(r['outcome']=='confirmed' for r in rows)==1
    assert sum(r['outcome']=='not_evaluated' for r in rows)==197
    # Re-sealing models an accidental new package assembled from mixed campaigns.
    # Valid file hashes alone must not make conflicting identities acceptable.
    if mismatch == 'row_campaign':
        path=public/'analysis/rows.json';data=load(path);data[0]['evaluation_id']='another-campaign'
    elif mismatch == 'metric_analysis':
        path=public/'analysis/metrics.json';data=load(path);data['analysis_id']='another-analysis'
    else:
        path=public/'registry.json';data=load(path);data['reports'][0]['source_snapshot_id']='another-snapshot'
    path.write_bytes(encoded(data))
    (public/'seal.json').unlink()
    seal(public)
    with pytest.raises(ValueError):generator.verify(public)
