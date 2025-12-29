// static/js/Dashboard.js
import React, { useState, useEffect } from 'react';
import { 
  Button, 
  Card, 
  Row, 
  Col, 
  Progress, 
  Alert, 
  Statistic,
  Space,
  Typography 
} from 'antd';
import { 
  SecurityScanOutlined, 
  StopOutlined,
  ReloadOutlined 
} from '@ant-design/icons';

// MODIFICA: Importa l'hook dal percorso statico
import { useThreatIntelligence } from './useThreatIntelligence';

const { Title, Text } = Typography;

const Dashboard = () => {
  const [essentialData, setEssentialData] = useState(null);
  const [showThreatSection, setShowThreatSection] = useState(false);
  
  const {
    data: threatData,
    loading: threatLoading,
    progress: threatProgress,
    processed: threatProcessed,
    total: threatTotal,
    threatsFound: threatThreatsFound,
    error: threatError,
    checkThreatIntelligence,
    cancelCheck
  } = useThreatIntelligence();

  // Carica solo dati essenziali al mount
  useEffect(() => {
    loadEssentialData();
  }, []);

  const loadEssentialData = async () => {
    try {
      const response = await fetch('/api/dashboard/essential');
      const data = await response.json();
      setEssentialData(data);
    } catch (error) {
      console.error('Errore caricamento dati essenziali:', error);
    }
  };

  const handleThreatCheck = (force = false) => {
    setShowThreatSection(true);
    checkThreatIntelligence(force);
  };

  return (
    <div className="dashboard" style={{ padding: '24px' }}>
      {/* Header Dashboard */}
      <div style={{ marginBottom: '24px' }}>
        <Title level={2}>Dashboard Dmarcus</Title>
        <Text type="secondary">Monitoraggio e Threat Intelligence</Text>
      </div>

      {/* Sezione Dati Essenziali */}
      <Row gutter={[16, 16]} style={{ marginBottom: '24px' }}>
        <Col span={8}>
          <Card>
            <Statistic 
              title="Report Totali" 
              value={essentialData?.totalReports || 0} 
            />
          </Card>
        </Col>
        <Col span={8}>
          <Card>
            <Statistic 
              title="Domini Monitorati" 
              value={essentialData?.domains || 0} 
            />
          </Card>
        </Col>
        <Col span={8}>
          <Card>
            <Statistic 
              title="Email Analizzate" 
              value={essentialData?.emailsAnalyzed || 0} 
            />
          </Card>
        </Col>
      </Row>

      {/* Sezione Threat Intelligence - Controllo Manuale */}
      <Card 
        title={
          <Space>
            <SecurityScanOutlined />
            <span>Threat Intelligence</span>
          </Space>
        }
        extra={
          <Space>
            {threatLoading ? (
              <Button 
                icon={<StopOutlined />}
                onClick={cancelCheck}
                danger
              >
                Interrompi
              </Button>
            ) : (
              <>
                <Button 
                  icon={<SecurityScanOutlined />}
                  onClick={() => handleThreatCheck(false)}
                  type="primary"
                >
                  Verifica Minacce
                </Button>
                <Button 
                  icon={<ReloadOutlined />}
                  onClick={() => handleThreatCheck(true)}
                >
                  Forza Aggiornamento
                </Button>
              </>
            )}
          </Space>
        }
        style={{ marginBottom: '24px' }}
      >
        {!showThreatSection && (
          <Alert
            message="Threat Intelligence non attiva"
            description="Clicca 'Verifica Minacce' per analizzare tutti gli IP nei tuoi report DMARC"
            type="info"
            showIcon
          />
        )}

        {showThreatSection && threatLoading && (
          <div>
            <Progress 
              percent={threatProgress} 
              status="active"
              strokeColor={{
                from: '#108ee9',
                to: '#87d068',
              }}
            />
            <div style={{ marginTop: '8px', textAlign: 'center' }}>
              <Text type="secondary">
                Processati {threatProcessed} di {threatTotal} IP • 
                Minacce trovate: {threatThreatsFound}
              </Text>
            </div>
          </div>
        )}

        {threatError && (
          <Alert
            message="Errore durante l'analisi"
            description={threatError}
            type="error"
            showIcon
          />
        )}

        {showThreatSection && threatData && !threatLoading && (
          <ThreatIntelligenceResults 
            data={threatData} 
            summary={{
              total: threatTotal,
              threatsFound: threatThreatsFound
            }}
          />
        )}
      </Card>

      {/* Altre sezioni della dashboard... */}
    </div>
  );
};

// Componente per mostrare i risultati
const ThreatIntelligenceResults = ({ data, summary }) => {
  const threats = data.filter(item => item.isThreat && !item.error);
  const errors = data.filter(item => item.error);

  return (
    <div>
      <Row gutter={[16, 16]} style={{ marginBottom: '16px' }}>
        <Col span={8}>
          <Statistic title="IP Totali Analizzati" value={summary.total} />
        </Col>
        <Col span={8}>
          <Statistic 
            title="Minacce Rilevate" 
            value={summary.threatsFound} 
            valueStyle={{ color: summary.threatsFound > 0 ? '#cf1322' : '#3f8600' }}
          />
        </Col>
        <Col span={8}>
          <Statistic 
            title="Tasso di Successo" 
            value={Math.round(((data.length - errors.length) / data.length) * 100)} 
            suffix="%" 
          />
        </Col>
      </Row>

      {threats.length > 0 && (
        <Alert
          message={`Trovate ${threats.length} minacce potenziali`}
          description={
            <ul>
              {threats.slice(0, 5).map((threat, index) => (
                <li key={index}>
                  <strong>{threat.ip}</strong> - Livello: {threat.threatLevel}
                </li>
              ))}
              {threats.length > 5 && <li>...e {threats.length - 5} altre</li>}
            </ul>
          }
          type="warning"
          showIcon
        />
      )}

      {errors.length > 0 && (
        <Alert
          message={`${errors.length} errori durante l'analisi`}
          type="info"
          showIcon
          style={{ marginTop: '16px' }}
        />
      )}
    </div>
  );
};

export default Dashboard;