import { register } from 'upload_detector_registry'
register({ name: 'Dradis::Plugins::Nessus', match: (sample) => /<NessusClientData_v2\b/.test(sample) })
